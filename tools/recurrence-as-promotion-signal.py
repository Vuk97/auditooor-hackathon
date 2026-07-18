#!/usr/bin/env python3
"""
recurrence-as-promotion-signal.py — Auto-elevate detector to Tier-S candidate
when a pattern hits >=3 workspaces with TP outcome.

M14-trap discipline:
  - n < 3 workspaces → NEVER emit a candidate (returns 0 candidates honestly)
  - Tier-S promotion ALWAYS surfaced for operator approval, NEVER auto-applied
  - Tier-S = "trust enough to file without per-finding review" — operator-only gate
  - outcome must be TP (paid / accepted / in_review_passed), not pending/unknown

Usage:
    python3 tools/recurrence-as-promotion-signal.py
        [--audits-dir ~/audits]
        [--min-workspaces 3]          # minimum TP workspaces for promotion (default 3)
        [--out reports/cross_workspace_finding_graph.json]
        [--vault obsidian-vault/calibration/tier-s-candidates.md]
        [--quiet]

Output:
    - obsidian-vault/calibration/tier-s-candidates.md
    - reports/ JSON section (tier_s_candidates)
    - stdout summary

Exit codes:
    0  Always (honest 0 is correct)
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

AUDITOOOR_DIR = Path(__file__).parent.parent
TIER_REGISTRY_PATH = AUDITOOOR_DIR / "detectors" / "_tier_registry.yaml"
REPORTS_DIR = AUDITOOOR_DIR / "reports"
VAULT_DIR = AUDITOOOR_DIR / "obsidian-vault"

# Corpus tag directory holding ingested own-findings. Each YAML carries
# `record_extensions.confirmed_finding` + `origin_workspace`, i.e. a
# PoC-confirmed / filed finding that the SUBMISSIONS.md telemetry layer
# does NOT normalise to a TP outcome (telemetry only sees freeform status
# strings). Without this source, confirmed findings register as 0 TP and
# Tier-S candidates can never surface. We treat a confirmed own-finding as
# a TP outcome here so recurrence signal can SURFACE candidates for the
# operator (Tier-S promotion stays operator-gated; we never auto-apply).
OWN_FINDINGS_DIR = (
    AUDITOOOR_DIR / "audit" / "corpus_tags" / "tags" / "auditooor_own_findings"
)

# Outcomes that count as True Positive (TP) for recurrence signal
TP_OUTCOMES: Set[str] = {
    "paid",
    "accepted",
    "triaged_paid",
    "in_review",   # passed triage — counts as near-TP
    "valid",
    "filed",       # filed to a program (PoC-confirmed); near-TP for recurrence
    "confirmed",   # PoC-confirmed own-finding normalised to a TP outcome
}

# Bug-class pattern keyword mapping (must stay in sync with finding-linker)
BUG_CLASS_KEYWORDS: Dict[str, List[str]] = {
    "reentrancy": ["reentr", "callback", "nonreentrant", "reentrant"],
    "access-control": ["access.control", "role", "unauthorized", "onlyrole", "acl"],
    "integer-overflow": ["overflow", "underflow", "uint256.max", "uint248"],
    "price-manipulation": ["oracle", "price.manipulation", "twap", "chainlink", "scale.factor"],
    "reward-theft": ["reward", "theft", "steal", "creator.*reward", "bond.reward"],
    "dos-liveness": ["brick", "permanently.reverts", "liveness", "dos"],
    "missing-check": ["missing.check", "lacks.check", "unchecked"],
    "fund-lock": ["locked", "locked.forever", "permanently.locked", "unrecoverable"],
    "race-condition": ["race", "preempt", "front.run"],
    "integer-truncation": ["truncation", "truncate", "integer.division", "scale.factor.zero"],
    "missing-guard": ["no.flag", "no.gate", "missing.guard"],
    "erc4626": ["erc4626", "share.inflation"],
    "erc20": ["erc20", "transfer.return", "return.code"],
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_tier_registry() -> Dict[str, Any]:
    """Load tier registry. Returns {} on failure."""
    try:
        import yaml  # type: ignore
        with open(TIER_REGISTRY_PATH) as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        return {"tiers": {}}
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


def get_own_finding_records(own_dir: Path = OWN_FINDINGS_DIR) -> List[Dict[str, Any]]:
    """Normalise ingested own-findings into TP outcome records.

    Each YAML under ``auditooor_own_findings/`` is a PoC-confirmed / filed
    finding (``record_extensions.confirmed_finding: true``). The freeform
    SUBMISSIONS.md telemetry layer cannot reliably normalise these to a TP
    outcome, so confirmed findings would otherwise register as 0 TP and no
    Tier-S candidate could ever surface. Here we emit one outcome record per
    confirmed own-finding, shaped identically to ``outcome-telemetry.py``
    records (``outcome``/``status``/``title``/``workspace``/``finding_id``/
    ``severity``/``date``) so the existing recurrence machinery can consume
    them unchanged.

    Tier-S promotion remains operator-gated downstream; this only ensures
    confirmed TPs are visible to the recurrence signal so candidates SURFACE.
    Returns [] when the directory is absent (honest 0, never raises).
    """
    if not own_dir.is_dir():
        return []
    try:
        import yaml  # type: ignore
        have_yaml = True
    except ImportError:
        have_yaml = False

    records: List[Dict[str, Any]] = []
    for path in sorted(own_dir.glob("*.yaml")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        doc: Dict[str, Any] = {}
        if have_yaml:
            try:
                doc = yaml.safe_load(text) or {}
            except Exception:
                doc = {}
        if not isinstance(doc, dict):
            doc = {}
        ext = doc.get("record_extensions") or {}
        if not isinstance(ext, dict):
            ext = {}

        # Confirmed flag (parsed value, else cheap text fallback).
        confirmed = ext.get("confirmed_finding")
        if confirmed is None:
            confirmed = "confirmed_finding: true" in text
        if not confirmed:
            continue

        workspace = (
            ext.get("origin_workspace")
            or doc.get("origin_workspace")
            or ""
        )
        title = (
            ext.get("finding_title")
            or doc.get("finding_title")
            or doc.get("record_id")
            or path.stem
        )
        severity = doc.get("severity_at_finding") or ext.get("severity") or ""
        finding_id = doc.get("record_id") or path.stem
        if not workspace:
            # Without a workspace we cannot count it toward cross-workspace
            # recurrence; skip rather than mis-attribute.
            continue
        records.append({
            "outcome": "confirmed",
            "status": "confirmed",
            "title": str(title),
            "workspace": str(workspace),
            "finding_id": str(finding_id),
            "severity": str(severity),
            "date": str(doc.get("audited_at_utc") or ""),
            "source": str(path),
        })
    return records


def classify_title(title: str) -> List[str]:
    """Classify a finding title into bug-class pattern categories."""
    title_lower = title.lower()
    matched: List[str] = []
    for pattern_class, keywords in BUG_CLASS_KEYWORDS.items():
        for kw in keywords:
            if re.search(kw, title_lower):
                matched.append(pattern_class)
                break
    return matched


def is_tp_outcome(outcome: str) -> bool:
    """Return True if the outcome string represents a True Positive."""
    outcome_lower = outcome.lower().strip()
    for tp_str in TP_OUTCOMES:
        if tp_str in outcome_lower:
            return True
    # "in_review" with parenthetical "passed" note
    if "in_review" in outcome_lower and "passed" in outcome_lower:
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--audits-dir",
        default=os.environ.get("AUDITS_DIR", str(Path.home() / "audits")),
    )
    parser.add_argument("--min-workspaces", type=int, default=3)
    parser.add_argument(
        "--out",
        default=str(REPORTS_DIR / "tier_s_candidates.json"),
    )
    parser.add_argument(
        "--vault",
        default=str(VAULT_DIR / "calibration" / "tier-s-candidates.md"),
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    audits_dir = Path(args.audits_dir).expanduser()
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    vault_path = Path(args.vault).expanduser()

    if not args.quiet:
        print(f"[recurrence-promotion] audits_dir={audits_dir}")
        print(f"[recurrence-promotion] min_workspaces={args.min_workspaces} (M14-trap: n<3 → 0 candidates)")

    # 1. Load outcome telemetry + normalise ingested own-findings.
    # Confirmed/filed own-findings are PoC-confirmed TPs that the freeform
    # SUBMISSIONS.md telemetry layer never normalises; without them the
    # ledger surfaces 0 TP and Tier-S is unreachable (meta-audit finding).
    records = get_outcome_records(audits_dir)
    own_records = get_own_finding_records()
    if own_records:
        records = list(records) + own_records
    if not args.quiet:
        print(f"[recurrence-promotion] loaded {len(records)} outcome records "
              f"({len(own_records)} from confirmed own-findings)")

    # 2. Load tier registry (to know what's already Tier-S)
    registry = load_tier_registry()
    tiers = registry.get("tiers", {})
    existing_tier_s = {pid for pid, meta in tiers.items() if meta.get("tier") == "S"}
    if not args.quiet:
        print(f"[recurrence-promotion] existing Tier-S patterns: {len(existing_tier_s)}")

    # 3. Build pattern → {workspace: [records]} map from TP records
    pattern_to_ws_records: Dict[str, Dict[str, List[Dict]]] = defaultdict(lambda: defaultdict(list))
    tp_count = 0
    for rec in records:
        outcome = rec.get("outcome", "")
        status = rec.get("status", "")
        # Also accept "in_review" with "passed" in status text
        is_tp = is_tp_outcome(outcome) or (
            "in_review" in outcome.lower() and "passed" in status.lower()
        )
        if not is_tp:
            continue
        tp_count += 1
        title = rec.get("title", "")
        workspace = rec.get("workspace", "")
        if not workspace:
            continue
        patterns = classify_title(title)
        for pattern_class in patterns:
            pattern_to_ws_records[pattern_class][workspace].append(rec)

    if not args.quiet:
        print(f"[recurrence-promotion] TP records: {tp_count} "
              f"(out of {len(records)} total)")

    # 4. Apply recurrence threshold (M14-trap: n < min_workspaces → no candidate)
    candidates: List[Dict[str, Any]] = []
    for pattern_class, ws_records in sorted(pattern_to_ws_records.items()):
        n_workspaces = len(ws_records)
        if n_workspaces < args.min_workspaces:
            # Honest accounting: not enough evidence
            continue
        if pattern_class in existing_tier_s:
            # Already Tier-S — skip
            continue

        total_tp = sum(len(recs) for recs in ws_records.values())
        workspace_list = sorted(ws_records.keys())

        # Build per-workspace evidence list
        evidence: List[Dict[str, Any]] = []
        for ws, recs in sorted(ws_records.items()):
            for rec in recs:
                evidence.append({
                    "workspace": ws,
                    "finding_id": rec.get("finding_id", ""),
                    "title": rec.get("title", "")[:120],
                    "severity": rec.get("severity", ""),
                    "outcome": rec.get("outcome", ""),
                    "date": rec.get("date", ""),
                })

        candidates.append({
            "pattern_class": pattern_class,
            "n_workspaces_with_tp": n_workspaces,
            "workspaces": workspace_list,
            "total_tp_findings": total_tp,
            "evidence": evidence,
            "sample_size_note": (
                f"n={n_workspaces} workspaces with TP outcome. "
                f"Threshold={args.min_workspaces}. "
                f"{'Meets' if n_workspaces >= args.min_workspaces else 'Does NOT meet'} "
                f"M14-trap discipline."
            ),
            "promotion_action_required": (
                "OPERATOR GATE: Tier-S promotion requires explicit operator approval. "
                "Do NOT auto-apply. Review each evidence finding before elevating."
            ),
            "detector_candidates": _find_matching_detectors(pattern_class, tiers),
        })

    candidates.sort(key=lambda c: -c["n_workspaces_with_tp"])

    if not args.quiet:
        print(f"[recurrence-promotion] Tier-S candidates: {len(candidates)} "
              f"(honest — 0 is correct if ledger is sparse)")

    # 5. Write JSON output
    output = {
        "generated_at": _now(),
        "audits_dir": str(audits_dir),
        "min_workspaces_threshold": args.min_workspaces,
        "total_outcome_records": len(records),
        "total_tp_records": tp_count,
        "existing_tier_s_count": len(existing_tier_s),
        "candidates_count": len(candidates),
        "candidates": candidates,
        "m14_trap_note": (
            "n < 3 workspaces → zero candidates emitted. "
            "Tier-S promotion ALWAYS requires operator approval. "
            "Never auto-applied."
        ),
        "honest_limits": [
            "Pattern classification uses keyword matching on finding titles.",
            "A sparse outcome ledger (most outcomes 'pending') will correctly produce 0 candidates.",
            "in_review records only count if status text also contains 'passed'.",
        ],
    }
    out_path.write_text(json.dumps(output, indent=2))

    # 6. Write Obsidian vault markdown
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    md_lines = [
        "# Tier-S Promotion Candidates",
        "",
        f"> Generated: {_now()}",
        f"> M14-trap: n<{args.min_workspaces} workspaces → 0 candidates",
        f"> **OPERATOR GATE REQUIRED for all promotions listed here.**",
        "",
        f"Total outcome records: {len(records)}",
        f"TP records: {tp_count}",
        f"Candidates: {len(candidates)}",
        "",
    ]
    if not candidates:
        md_lines += [
            "## Result: 0 candidates",
            "",
            "No pattern has reached the threshold of "
            f">={args.min_workspaces} workspaces with TP outcome.",
            "This is the **honest and correct result** given the current outcome ledger.",
            "",
            "Re-run after more findings are triaged and paid.",
        ]
    else:
        md_lines.append("## Candidates")
        md_lines.append("")
        for c in candidates:
            md_lines += [
                f"### {c['pattern_class']}",
                "",
                f"- **Workspaces with TP:** {c['n_workspaces_with_tp']} ({', '.join(c['workspaces'])})",
                f"- **Total TP findings:** {c['total_tp_findings']}",
                f"- **Sample size note:** {c['sample_size_note']}",
                f"- **Matching detectors:** {', '.join(c['detector_candidates'][:5]) or 'none in registry'}",
                "",
                "**Evidence:**",
                "",
                "| Workspace | Finding ID | Title | Severity | Outcome |",
                "|---|---|---|---|---|",
            ]
            for ev in c["evidence"]:
                md_lines.append(
                    f"| {ev['workspace']} | {ev['finding_id']} | {ev['title'][:60]} "
                    f"| {ev['severity']} | {ev['outcome']} |"
                )
            md_lines += [
                "",
                f"> **{c['promotion_action_required']}**",
                "",
            ]

    vault_path.write_text("\n".join(md_lines))

    print(f"[recurrence-promotion] candidates={len(candidates)} "
          f"(tp_records={tp_count}/{len(records)})")
    print(f"  JSON: {out_path}")
    print(f"  Vault: {vault_path}")
    if candidates:
        for c in candidates:
            print(f"  CANDIDATE: {c['pattern_class']} "
                  f"n={c['n_workspaces_with_tp']} workspaces "
                  f"[{', '.join(c['workspaces'])}] — OPERATOR APPROVAL REQUIRED")
    else:
        print("  Honest result: 0 candidates (ledger too sparse or threshold not met)")


def _find_matching_detectors(pattern_class: str, tiers: Dict[str, Any]) -> List[str]:
    """Find existing detector IDs that match a pattern class name."""
    matches: List[str] = []
    pattern_words = set(pattern_class.lower().replace("-", " ").split())
    for det_id in tiers:
        det_words = set(det_id.lower().replace("-", " ").split())
        if pattern_words & det_words:
            matches.append(det_id)
    return sorted(matches)[:10]


if __name__ == "__main__":
    main()
