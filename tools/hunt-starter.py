#!/usr/bin/env python3
"""hunt-starter.py - Phase -1 A / WF-3 REC-1.

Moves R-rule pre-screening UPSTREAM from submit-time to hunt-starter-time.
Reads existing engagement artifacts (engage_report.md, exploit_queue.json,
mined_findings_obligations.json) and runs the existing R-rule gates against
each candidate BEFORE a worker is dispatched on it.

By the time a candidate reaches submit-time, a worker has often spent
hours building the evidence. Catching "would-be-dropped" candidates at
hunt-time (e.g. designed-as-intended, prior-audit-dupe, rubric-row-missing)
saves 1-N worker-hours per skipped candidate.

Per the WF-3 RECommendation (highest-leverage WF finding), this uses
ONLY EXISTING TOOLS. No new infrastructure. The 5 R-rule gates we wire:

  R45 (designed-as-intended-precheck.py)         - Check #93
  R47 (acknowledged-wont-fix-check.py)            - Check #96
  R52 (rubric-row-coverage-check.py)              - Check #97
  R53 (prior-audit-finding-supersede-check.py)    - Check #99
  L31 (duplicate-preflight-check.py)              - Check #49

Plus two optional restored tools (graceful no-op when absent per RESTORE-1):

  tools/pattern-migration-alert.py        - cross-engagement PAID match
  tools/scan-report-thicken.py            - classifier scoring

Verdict vocabulary (per candidate):

  HUNT-READY                            - all gates pass; dispatch a worker
  LIKELY-DUPE-SKIP                      - L31 or R47 flags pre-existing
  LIKELY-OOS-SKIP                       - rubric/scope mismatch
  RUBRIC-NO-ROW-SKIP                    - R52 says no row for impact class
  DESIGN-CHOICE-SKIP                    - R45 says designed-as-intended
  PAID-FINDING-MATCH-HIGH-PRIORITY      - cross-eng PAID-finding match

The output is two artifacts at .auditooor/hunt_candidates_ranked.{json,md}.

Usage:
    python3 tools/hunt-starter.py --workspace <ws> [--limit N] [--json]

The --workspace arg points at an audit workspace (e.g. ~/audits/dydx).
The tool reads:
    <ws>/engage_report.md                         (required if no queue/oblig)
    <ws>/.auditooor/exploit_queue.json            (optional)
    <ws>/.auditooor/exploit_queue.source_mined.json (optional; source-backed queue rows)
    <ws>/.auditooor/mined_findings_obligations.json (optional)
    <ws>/docs/LIVE_TARGET_REPORT.json             (optional; P5 context pack)

Schema: auditooor.hunt_starter.v1
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.hunt_starter.v1"

# ---------------------------------------------------------------------------
# Tool locations - resolved relative to this file's tools/ directory.

THIS_FILE = Path(__file__).resolve()
TOOLS_DIR = THIS_FILE.parent
ROOT = TOOLS_DIR.parent

R45 = TOOLS_DIR / "designed-as-intended-precheck.py"
R47 = TOOLS_DIR / "acknowledged-wont-fix-check.py"
R52 = TOOLS_DIR / "rubric-row-coverage-check.py"
R53 = TOOLS_DIR / "prior-audit-finding-supersede-check.py"
L31 = TOOLS_DIR / "duplicate-preflight-check.py"

# Optional restored tools - per RESTORE-1; missing is fine.
PATTERN_MIGRATION = TOOLS_DIR / "pattern-migration-alert.py"
SCAN_REPORT_THICKEN = TOOLS_DIR / "scan-report-thicken.py"

# ---------------------------------------------------------------------------
# Pillar P1 (invariant library) + P3 (anti-pattern catalog) data sources.
# WIRING-1-MAKE-AUDIT-CONSUME-PILLARS lane (2026-05-23): the hunt-starter
# annotates each candidate with the matched P1 invariant IDs + P3 pattern
# IDs joined by (category, target_lang) derived from the detector cluster
# slug. Mirrors live-target-intelligence-report.py v2 compose logic, kept
# inline so hunt-starter stays standalone (no cross-tool dependency).
#
# When ``invariants_pilot_audited.jsonl`` exists (output of the
# P1-PILOT-SUBSET-AUDIT lane), it is preferred as PRIMARY-KEY input over
# the full 500-entry library; fall back to the full library otherwise.

P1_INV_EXTRACTED = ROOT / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl"
P1_INV_PILOT = ROOT / "audit" / "corpus_tags" / "derived" / "invariants_pilot.jsonl"
P1_INV_PILOT_AUDITED = ROOT / "audit" / "corpus_tags" / "derived" / "invariants_pilot_audited.jsonl"
P3_PATTERNS_DIR = ROOT / "obsidian-vault" / "anti-patterns" / "v2"
LIVE_TARGET_REPORT_REL = Path("docs") / "LIVE_TARGET_REPORT.json"

# Cluster-slug-token -> (p1_category, p3_category). Same table as
# live-target-intelligence-report.py CLUSTER_TOKEN_TO_CATEGORY. Kept
# inline rather than imported so hunt-starter stays self-contained.
CLUSTER_TOKEN_TO_CATEGORY: Dict[str, Tuple[str, str]] = {
    "race":               ("atomicity",   "atomicity-and-ordering"),
    "reentrancy":         ("atomicity",   "reentrancy"),
    "skip_allowed":       ("ordering",    "atomicity-and-ordering"),
    "external_call":      ("ordering",    "external-call-handling"),
    "parse":              ("bounds",      "bounds-and-bounds-checks"),
    "panic":              ("bounds",      "bounds-and-bounds-checks"),
    "unbounded":          ("bounds",      "bounds-and-bounds-checks"),
    "timestamp":          ("determinism", "block-timestamp-randomness"),
    "randomness":         ("determinism", "block-timestamp-randomness"),
    "tx_origin":          ("authorization", "authorization"),
    "auth":               ("authorization", "authorization"),
    "unchecked":          ("conservation", "external-call-handling"),
    "overflow":           ("bounds",      "bounds-and-bounds-checks"),
    "underflow":          ("bounds",      "bounds-and-bounds-checks"),
}

# CAP-003 (2026-05-24, hyperbridge anchor): keyword-substring matching
# for descriptive kebab-case cluster slugs that the token-prefix resolver
# above cannot recognize. Kept in sync with the same table in
# live-target-intelligence-report.py CLUSTER_KEYWORD_TO_CATEGORY.
CLUSTER_KEYWORD_TO_CATEGORY: List[Tuple[str, str, str]] = [
    ("external-call-before-state",      "ordering",     "external-call-handling"),
    ("reentrancy",                      "atomicity",    "reentrancy"),
    ("unchecked-low-level-call",        "ordering",     "external-call-handling"),
    ("unchecked",                       "conservation", "external-call-handling"),
    ("transfer-return-not-checked",     "conservation", "external-call-handling"),
    ("raw-transfer-no-bool-check",      "conservation", "external-call-handling"),
    ("fee-on-transfer-not-accounted",   "conservation", "custody-and-accounting"),
    ("access-control",                  "authorization", "authorization"),
    ("unprotected-initialize",          "authorization", "authorization"),
    ("initialize-multiple-calls",       "authorization", "authorization"),
    ("initializer-modifier",            "authorization", "authorization"),
    ("setters-with-no-access-control",  "authorization", "authorization"),
    ("missing-unpause",                 "authorization", "authorization"),
    ("pausable-no-unpause-exposed",     "authorization", "authorization"),
    ("constructor-no-zero-address",     "authorization", "authorization"),
    ("eoa-restricted-via-extcodesize",  "authorization", "authorization"),
    ("lzReceive-no-sender-check",       "authorization", "authorization"),
    ("signature-without-nonce",         "authorization", "authorization"),
    ("erc-2771",                        "authorization", "authorization"),
    ("msgSender-forgery",               "authorization", "authorization"),
    ("downcast",                        "bounds",       "bounds-and-bounds-checks"),
    ("uint256-to-int256",               "bounds",       "bounds-and-bounds-checks"),
    ("int256-cast",                     "bounds",       "bounds-and-bounds-checks"),
    ("division-by-zero",                "bounds",       "bounds-and-bounds-checks"),
    ("division-to-zero",                "bounds",       "bounds-and-bounds-checks"),
    ("unbounded-loop",                  "bounds",       "bounds-and-bounds-checks"),
    ("excessive-erc20-withdrawal",      "custody",      "custody-and-accounting"),
    ("hardcoded-sqrtPriceLimitX96",     "determinism",  "randomness-and-determinism"),
    ("uniswap-v4-poolkey-no-whitelist", "authorization", "authorization"),
    ("delegatecall-to-state",           "authorization", "authorization"),
    ("state-variable-shadowing",        "determinism",  "atomicity-and-ordering"),
    ("named-return-shadows-storage",    "determinism",  "atomicity-and-ordering"),
    ("delete-enumerable-set-struct",    "determinism",  "atomicity-and-ordering"),
    ("eip1153-transient-auth",          "authorization", "authorization"),
    ("erc165-missing",                  "authorization", "authorization"),
]

# Composability bump thresholds: candidates with >=2 matched P1 invariants
# AND >=1 matched P3 pattern get promoted to the new HUNT-READY-RICH-CONTEXT
# verdict bucket.
HUNT_READY_RICH_MIN_P1 = int(os.environ.get("AUDITOOOR_HUNT_RICH_MIN_P1", "2"))
HUNT_READY_RICH_MIN_P3 = int(os.environ.get("AUDITOOOR_HUNT_RICH_MIN_P3", "1"))


# ---------------------------------------------------------------------------
# Verdict labels (constants - tests assert against these).

VERDICT_HUNT_READY = "HUNT-READY"
VERDICT_HUNT_READY_RICH_CONTEXT = "HUNT-READY-RICH-CONTEXT"
VERDICT_LIKELY_DUPE_SKIP = "LIKELY-DUPE-SKIP"
VERDICT_LIKELY_OOS_SKIP = "LIKELY-OOS-SKIP"
VERDICT_RUBRIC_NO_ROW_SKIP = "RUBRIC-NO-ROW-SKIP"
VERDICT_DESIGN_CHOICE_SKIP = "DESIGN-CHOICE-SKIP"
VERDICT_PAID_MATCH = "PAID-FINDING-MATCH-HIGH-PRIORITY"
# Candidate carries no rubric severity (e.g. a raw source-mined grep hit). It
# cannot be assessed by the severity/rubric gates - they all collapse to a
# no-row skip - so it is fast-pathed here instead of spending ~7 gate
# subprocesses on it. Still gets a verdict row, so coverage accounting is intact.
VERDICT_NO_SEVERITY_SKIP = "NO-SEVERITY-TRIAGE-SKIP"

# Order matters - PAID match wins; then skip-class; then RICH-CONTEXT
# (ranked above plain ready); then plain HUNT-READY.
VERDICT_PRIORITY = [
    VERDICT_PAID_MATCH,
    VERDICT_DESIGN_CHOICE_SKIP,
    VERDICT_RUBRIC_NO_ROW_SKIP,
    VERDICT_LIKELY_DUPE_SKIP,
    VERDICT_LIKELY_OOS_SKIP,
    VERDICT_NO_SEVERITY_SKIP,
    VERDICT_HUNT_READY_RICH_CONTEXT,
    VERDICT_HUNT_READY,
]


# ---------------------------------------------------------------------------
# Cluster + queue-row parsers.

CLUSTER_HEADER_RE = re.compile(
    r"^### Cluster:\s*`([^`]+)`\s*\((\d+)\s+hits?\)", re.MULTILINE
)
HIT_LINE_RE = re.compile(
    r"^- \*\*\[(\w+)\]\s*`([^`]+)`\*\*\s*-\s*`([^`]+)`", re.MULTILINE
)


def parse_engage_report(text: str) -> List[Dict[str, Any]]:
    """Parse engage_report.md into clusters with (detector, severity, hits, sample_paths).

    Returns one dict per cluster, with up to 5 sample (severity, path) hit tuples.
    """
    clusters: List[Dict[str, Any]] = []
    # Each cluster block is bounded by a "### Cluster:" header and the next one.
    headers = list(CLUSTER_HEADER_RE.finditer(text))
    if not headers:
        return clusters
    for i, m in enumerate(headers):
        start = m.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        block = text[start:end]
        detector = m.group(1).strip()
        hit_count = int(m.group(2))
        # Pull up to 5 sample hits.
        samples: List[Dict[str, str]] = []
        for hit in HIT_LINE_RE.finditer(block):
            severity = hit.group(1).strip()
            # group 2 is the detector again; we already have it. group 3 is path.
            path = hit.group(3).strip()
            samples.append({"severity": severity, "path": path})
            if len(samples) >= 5:
                break
        clusters.append({
            "source": "engage_report.md",
            "candidate_id": f"cluster:{detector}",
            "detector": detector,
            "hit_count": hit_count,
            "samples": samples,
            "severity_max": (samples[0]["severity"] if samples else "LOW"),
        })
    return clusters


def parse_exploit_queue(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse exploit_queue.json into normalised candidate rows."""
    out: List[Dict[str, Any]] = []
    rows = data.get("queue") or data.get("rows") or []
    for r in rows:
        if not isinstance(r, dict):
            continue
        lead_id = r.get("lead_id") or r.get("id") or "unknown"
        title = r.get("title") or "(no title)"
        sev = (r.get("likely_severity") or r.get("severity") or "medium").strip()
        # Normalize to uppercase tier label.
        sev_norm = sev.upper() if sev else "MEDIUM"
        out.append({
            "source": "exploit_queue.json",
            "candidate_id": f"eq:{lead_id}",
            "lead_id": lead_id,
            "title": title,
            "severity_max": sev_norm,
            "attack_class": r.get("attack_class") or "unknown",
            "impact_path": r.get("impact_path") or "unknown",
            "root_cause_hypothesis": r.get("root_cause_hypothesis") or "",
            "source_refs": r.get("source_refs") or [],
            "impact_contract_id": r.get("impact_contract_id") or "",
            "impact_contract_status": r.get("impact_contract_status") or "",
            "impact_contract_gaps": r.get("impact_contract_gaps") or [],
        })
    return out


_SOURCE_MINED_TERMINAL_STATUSES = {
    "killed",
    "disproved",
    "closed_negative",
    "false_positive",
    "not_candidate",
    "not_exploitable",
    "duplicate",
    "oos",
    "out_of_scope",
}


def parse_source_mined_queue(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse exploit_queue.source_mined.json into first-class hunt rows.

    Source-mined rows are only useful to hunt-starter once they survived into
    a non-terminal queue state. We preserve their source artifact and impact
    contract fields so downstream dispatch can see whether a row is
    source-backed but still impact-contract-blocked.
    """
    out: List[Dict[str, Any]] = []
    rows = data.get("queue") or data.get("rows") or []
    for r in rows:
        if not isinstance(r, dict):
            continue
        proof_status = str(r.get("proof_status") or "").strip().lower()
        if r.get("row_is_advisory") is True or proof_status in _SOURCE_MINED_TERMINAL_STATUSES:
            continue
        lead_id = r.get("lead_id") or r.get("id") or r.get("row_id") or "unknown"
        title = r.get("title") or "(no title)"
        sev = (r.get("likely_severity") or r.get("severity") or "medium").strip()
        sev_norm = sev.upper() if sev else "MEDIUM"
        out.append({
            "source": "exploit_queue.source_mined.json",
            "candidate_id": f"smq:{lead_id}",
            "lead_id": lead_id,
            "title": title,
            "severity_max": sev_norm,
            "attack_class": r.get("attack_class") or "unknown",
            "impact_path": r.get("impact_path") or r.get("selected_impact") or "unknown",
            "root_cause_hypothesis": r.get("root_cause_hypothesis") or "",
            "source_refs": r.get("source_refs") or [],
            "source_artifact_path": r.get("source_artifact_path") or "",
            "source_artifacts_complete": bool(r.get("source_artifacts_complete")),
            "proof_status": r.get("proof_status") or "",
            "quality_gate_status": r.get("quality_gate_status") or "",
            "learning_route": r.get("learning_route") or "",
            "impact_contract_id": r.get("impact_contract_id") or "",
            "impact_contract_status": r.get("impact_contract_status") or "",
            "impact_contract_gaps": r.get("impact_contract_gaps") or [],
            "listed_impact_selected": r.get("listed_impact_selected") or r.get("selected_impact") or "",
            "listed_impact_proven": bool(r.get("listed_impact_proven")),
            "negative_control": r.get("negative_control") or "",
        })
    return out


def parse_mined_obligations(data: Any) -> List[Dict[str, Any]]:
    """Parse mined_findings_obligations.json into normalised candidate rows.

    The schema varies historically. We accept:
      {"obligations": [ {id, title, severity, file:line, ...}, ... ]}
      [{...}, ...] - top-level list.
    """
    out: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        rows = data.get("obligations") or data.get("rows") or data.get("findings") or []
    elif isinstance(data, list):
        rows = data
    else:
        rows = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        cid = r.get("id") or r.get("finding_id") or r.get("obligation_id") or "unknown"
        title = r.get("title") or r.get("name") or "(no title)"
        sev = (r.get("severity") or r.get("likely_severity") or "medium").strip()
        sev_norm = sev.upper() if sev else "MEDIUM"
        out.append({
            "source": "mined_findings_obligations.json",
            "candidate_id": f"mob:{cid}",
            "lead_id": cid,
            "title": title,
            "severity_max": sev_norm,
            "file_line": r.get("file_line") or r.get("location") or "",
            "anchor": r.get("anchor") or "",
        })
    return out


# ---------------------------------------------------------------------------
# Pillar P1 (invariant library) + P3 (anti-pattern catalog) loaders.
# Replicate the live-target-intelligence-report v2 compose logic locally
# so hunt-starter can annotate candidates without taking a runtime
# dependency on that tool.

_YAML_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$")


def _parse_pattern_yaml(text: str) -> Dict[str, str]:
    """Tiny YAML reader for P3 anti-pattern yaml files (no PyYAML dep)."""
    out: Dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith(" ") or line.startswith("\t") or line.startswith("#"):
            continue
        m = _YAML_KEY_RE.match(line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if val in ("|", ">"):
            continue
        if val:
            if (val.startswith('"') and val.endswith('"')) or (
                val.startswith("'") and val.endswith("'")
            ):
                val = val[1:-1]
            out[key] = val
    return out


def _read_jsonl_invariants(path: Path) -> List[Dict[str, Any]]:
    """Read a jsonl invariant file; return list of dicts (errors skipped)."""
    out: List[Dict[str, Any]] = []
    if not path.is_file():
        return out
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return out
    return out


def load_p1_invariants(
    pilot_audited: Optional[Path] = None,
    pilot: Optional[Path] = None,
    extracted: Optional[Path] = None,
) -> Tuple[Dict[str, List[str]], str]:
    """Load P1 invariants indexed by ``(category, target_lang)`` key.

    Returns ``(index, source_label)`` where ``source_label`` is one of:
      - ``pilot-audited``    -> pilot_audited.jsonl present, used as PRIMARY-KEY
      - ``full-library``     -> pilot_audited absent; full pilot+extracted used
      - ``empty``            -> no P1 source files present
    """
    pa = pilot_audited if pilot_audited is not None else P1_INV_PILOT_AUDITED
    p = pilot if pilot is not None else P1_INV_PILOT
    e = extracted if extracted is not None else P1_INV_EXTRACTED

    index: Dict[str, List[str]] = {}
    source_label = "empty"
    if pa.is_file():
        # P1-PILOT-SUBSET-AUDIT preferred path.
        recs = _read_jsonl_invariants(pa)
        if recs:
            source_label = "pilot-audited"
        for rec in recs:
            inv_id = rec.get("invariant_id")
            cat = rec.get("category")
            lang = rec.get("target_lang") or "any"
            if not inv_id or not cat:
                continue
            key = f"{cat}|{lang}"
            index.setdefault(key, []).append(str(inv_id))
    else:
        # Fallback: full library (pilot + extracted).
        for path in (p, e):
            recs = _read_jsonl_invariants(path)
            if recs and source_label == "empty":
                source_label = "full-library"
            for rec in recs:
                inv_id = rec.get("invariant_id")
                cat = rec.get("category")
                lang = rec.get("target_lang") or "any"
                if not inv_id or not cat:
                    continue
                key = f"{cat}|{lang}"
                index.setdefault(key, []).append(str(inv_id))
    for key in list(index.keys()):
        index[key] = sorted(set(index[key]))
    return index, source_label


def load_p3_patterns(base: Optional[Path] = None) -> Dict[str, List[str]]:
    """Load P3 anti-pattern catalog indexed by ``(category, language)`` key."""
    root = base if base is not None else P3_PATTERNS_DIR
    index: Dict[str, List[str]] = {}
    if not root.is_dir():
        return index
    for lang_dir in sorted(root.iterdir()):
        if not lang_dir.is_dir():
            continue
        for yaml_path in sorted(lang_dir.glob("*.yaml")):
            try:
                text = yaml_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            fields = _parse_pattern_yaml(text)
            pid = fields.get("pattern_id")
            cat = fields.get("category")
            lang = fields.get("language") or lang_dir.name
            if not pid or not cat:
                continue
            key = f"{cat}|{lang}"
            index.setdefault(key, []).append(str(pid))
    for key in list(index.keys()):
        index[key] = sorted(set(index[key]))
    return index


def _cluster_lang(cluster_id: str, file_hint: Optional[str] = None) -> str:
    """Extract target language from cluster slug prefix.

    CAP-003 (2026-05-24): when the slug has no lang prefix (e.g.
    descriptive kebab-case ``external-call-before-state-update``),
    fall back to the file extension via ``file_hint``.
    """
    if cluster_id:
        prefix = cluster_id.split(".", 1)[0].lower()
        if prefix == "go":
            return "go"
        if prefix in ("sol", "solidity"):
            return "solidity"
        if prefix == "rust":
            return "rust"
        if prefix == "move":
            return "move"
    if file_hint:
        fh = file_hint.lower()
        path_only = fh.split(":", 1)[0]  # strip ":<line>" suffix
        if path_only.endswith(".go"):
            return "go"
        if path_only.endswith(".sol"):
            return "solidity"
        if path_only.endswith(".rs"):
            return "rust"
        if path_only.endswith(".move"):
            return "move"
    return "any"


def _resolve_cluster_category_keyword(cluster_id: str) -> Tuple[Optional[str], Optional[str]]:
    """CAP-003 fallback: keyword-substring matching for descriptive slugs."""
    if not cluster_id:
        return (None, None)
    cid_lower = cluster_id.lower()
    for keyword, p1_cat, p3_cat in CLUSTER_KEYWORD_TO_CATEGORY:
        if keyword.lower() in cid_lower:
            return (p1_cat or None, p3_cat or None)
    return (None, None)


def _resolve_cluster_category(cluster_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Map a detector-cluster slug to ``(p1_category, p3_category)``.

    Resolver chain: token-prefix table first, then CAP-003 keyword fallback.
    """
    if not cluster_id:
        return (None, None)
    tokens = cluster_id.split(".")
    for tok in tokens:
        if tok in CLUSTER_TOKEN_TO_CATEGORY:
            p1, p3 = CLUSTER_TOKEN_TO_CATEGORY[tok]
            return (p1 or None, p3 or None)
    return _resolve_cluster_category_keyword(cluster_id)


def match_p1_for_candidate(
    candidate: Dict[str, Any],
    p1_index: Dict[str, List[str]],
    max_ids: int = 5,
) -> List[str]:
    """Return P1 invariant_ids matched by the candidate's detector cluster.

    CAP-003: when the cluster slug has no lang prefix, derive lang from
    the candidate's ``file_line`` field. When lang is still ``any``, scan
    every ``<cat>|*`` bucket so descriptive slugs still surface invariants.
    """
    # Engage_report-sourced candidates carry detector; queue/obligation
    # candidates do not - skip cleanly.
    cluster_id = candidate.get("detector") or ""
    if not cluster_id:
        return []
    p1_cat, _ = _resolve_cluster_category(cluster_id)
    if not p1_cat:
        return []
    file_hint = candidate.get("file_line") or candidate.get("file_path") or ""
    lang = _cluster_lang(cluster_id, file_hint=file_hint)
    out: List[str] = []
    out.extend(p1_index.get(f"{p1_cat}|{lang}", []))
    if lang != "any":
        out.extend(p1_index.get(f"{p1_cat}|any", []))
    else:
        # CAP-003: lang unknown - scan every language bucket for category.
        for key, ids in p1_index.items():
            if key.startswith(f"{p1_cat}|") and key != f"{p1_cat}|{lang}":
                out.extend(ids)
    seen: set = set()
    deduped: List[str] = []
    for x in out:
        if x in seen:
            continue
        seen.add(x)
        deduped.append(x)
    return deduped[:max_ids]


def match_p3_for_candidate(
    candidate: Dict[str, Any],
    p3_index: Dict[str, List[str]],
) -> List[str]:
    """Return P3 pattern_ids matched by the candidate's detector cluster.

    Emits the documented ``no-P3-match:<cat>:<lang>`` sentinel when the
    category resolves but no per-language P3 yaml exists yet (e.g. Go
    clusters with only Solidity P3 yamls today).
    """
    cluster_id = candidate.get("detector") or ""
    if not cluster_id:
        return []
    _, p3_cat = _resolve_cluster_category(cluster_id)
    if not p3_cat:
        return []
    file_hint = candidate.get("file_line") or candidate.get("file_path") or ""
    lang = _cluster_lang(cluster_id, file_hint=file_hint)
    ids = list(p3_index.get(f"{p3_cat}|{lang}", []))
    if ids:
        return ids
    return [f"no-P3-match:{p3_cat}:{lang}"]


def load_live_target_context(workspace: Path) -> Tuple[Dict[str, Dict[str, Any]], str]:
    """Load P5 live-target context indexed by cluster_id.

    The report is optional. When present, it gives hunt-starter a real context
    pack from ``make live-target-intel`` instead of only generic queue rows.
    """
    path = workspace / LIVE_TARGET_REPORT_REL
    if not path.is_file():
        return {}, "missing"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}, "unreadable"
    if not isinstance(payload, dict):
        return {}, "unreadable"
    index: Dict[str, Dict[str, Any]] = {}
    for row in payload.get("prioritized_hunt_list") or payload.get("entry_points") or []:
        if not isinstance(row, dict):
            continue
        cluster_id = str(row.get("cluster_id") or "").strip()
        if not cluster_id:
            continue
        index.setdefault(cluster_id, {
            "cluster_id": cluster_id,
            "hunt_priority": row.get("hunt_priority") or "",
            "engage_severity_score": row.get("engage_severity_score"),
            "file_line": row.get("file_line") or "",
            "matched_anti_patterns": row.get("matched_anti_patterns") or [],
            "matched_p1_invariants": row.get("matched_p1_invariants") or row.get("p1_invariant_hits") or [],
            "composability_score": row.get("composability_score"),
        })
    return index, "loaded" if index else "empty"


def match_live_target_for_candidate(
    candidate: Dict[str, Any],
    live_index: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    cluster_id = str(candidate.get("detector") or "").strip()
    if not cluster_id:
        return {}
    return dict(live_index.get(cluster_id) or {})


# ---------------------------------------------------------------------------
# Synthetic-draft builder.
#
# Each R-rule tool takes a draft markdown file. We do not have a real draft
# at hunt-time, so we synthesise a minimal stub with the candidate's
# severity, title, and file:line so the gates can fire their heuristics.

def synth_draft(candidate: Dict[str, Any], asset_selector: str = "polymarket") -> str:
    """Build a synthetic draft markdown for the candidate.

    The shape mirrors what the R-rule tools expect at minimum:
      - a Severity: header
      - a Title: line
      - a Summary section with the candidate's title prose
      - an Impact section (used by R52 word-overlap)
      - a body referencing the candidate's file:line if available

    asset_selector is consumed by L31's Cantina path.
    """
    sev_label = candidate.get("severity_max", "Medium")
    # Normalise to Cap title-case for the Severity header
    sev_cap = sev_label.capitalize() if sev_label else "Medium"

    title = candidate.get("title") or candidate.get("detector") or candidate.get("candidate_id", "candidate")
    detector = candidate.get("detector", "")
    file_line = candidate.get("file_line", "")
    samples = candidate.get("samples") or []

    # Pull a representative path/snippet for body so file extraction works.
    body_paths: List[str] = []
    if file_line:
        body_paths.append(file_line)
    for s in samples[:3]:
        if isinstance(s, dict) and s.get("path"):
            body_paths.append(s["path"])
    for r in candidate.get("source_refs") or []:
        if isinstance(r, str):
            body_paths.append(r)

    # Pick an impact phrase from common rubric vocab so R52 has something to
    # word-overlap against. We deliberately use the rubric-listed impact
    # CRITICAL / HIGH / MEDIUM / LOW class wording from typical SEVERITY.md.
    sev_lower = sev_cap.lower()
    if sev_lower in ("critical",):
        impact = "Significant loss of user funds via the cited path."
    elif sev_lower in ("high",):
        impact = "Network-level downtime or matching engine degradation via the cited path."
    elif sev_lower in ("medium",):
        impact = "Failure in non-core products that degrades protocol guarantees."
    else:
        impact = "Display or event-parsing issue misleading users."

    body_paths_md = "\n".join(f"- `{p}`" for p in body_paths) if body_paths else "- (no anchors yet)"

    return f"""<!-- cantina-asset: {asset_selector} -->
# {title}

Severity: {sev_cap}
Title: {title}

## Summary

Candidate emitted from hunt-starter pre-screening. Detector: `{detector}`.
The candidate's root cause hypothesis is: {candidate.get('root_cause_hypothesis', 'unspecified')}.

## Impact

{impact}

## Vulnerability anchors

{body_paths_md}
"""


# ---------------------------------------------------------------------------
# Gate runner.

def _run_subprocess_json(
    tool_path: Path,
    args: List[str],
    timeout: int = 60,
) -> Tuple[int, Dict[str, Any], str]:
    """Run `python3 <tool_path> <args>` capturing JSON stdout.

    Returns (returncode, parsed_json_or_error_dict, raw_stdout).
    """
    if not tool_path.exists():
        return -1, {"error": "tool-missing", "tool": str(tool_path)}, ""
    cmd = ["python3", str(tool_path)] + args
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(ROOT),
        )
    except subprocess.TimeoutExpired:
        return -2, {"error": "timeout", "cmd": cmd}, ""
    except Exception as exc:
        return -3, {"error": "exec-failed", "msg": str(exc), "cmd": cmd}, ""
    raw = proc.stdout or ""
    parsed: Dict[str, Any] = {}
    if raw.strip():
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"error": "json-parse-failed", "raw_snippet": raw[:200]}
    if proc.returncode != 0 and not parsed:
        parsed = {"error": "nonzero-exit-no-json", "rc": proc.returncode, "stderr": (proc.stderr or "")[:200]}
    return proc.returncode, parsed, raw


def run_gates(
    candidate: Dict[str, Any],
    workspace: Path,
    tmpdir: Path,
) -> Dict[str, Any]:
    """Run all 5 R-rule gates + 2 optional restored tools against the candidate.

    Returns a dict with per-gate (verdict, raw_json) and the rolled-up
    hunt-verdict label.
    """
    # Build a synthetic draft into tmpdir.
    cid = re.sub(r"[^a-zA-Z0-9._-]", "_", candidate.get("candidate_id", "candidate"))
    draft_path = tmpdir / f"{cid}.draft.md"
    draft_path.write_text(synth_draft(candidate), encoding="utf-8")

    results: Dict[str, Any] = {
        "candidate_id": candidate.get("candidate_id"),
        "severity_max": candidate.get("severity_max"),
        "gates": {},
    }

    # ---- R45 designed-as-intended ----
    rc, parsed, _ = _run_subprocess_json(
        R45,
        [str(draft_path), "--workspace", str(workspace), "--json"],
    )
    results["gates"]["R45"] = {"rc": rc, "verdict": parsed.get("verdict"), "reason": parsed.get("reason")}

    # ---- R47 acknowledged-wont-fix ----
    rc, parsed, _ = _run_subprocess_json(
        R47,
        [str(draft_path), "--workspace", str(workspace), "--json"],
    )
    results["gates"]["R47"] = {"rc": rc, "verdict": parsed.get("verdict"), "reason": parsed.get("reason")}

    # ---- R52 rubric-row-coverage ----
    rc, parsed, _ = _run_subprocess_json(
        R52,
        [str(draft_path), "--workspace", str(workspace), "--json"],
    )
    results["gates"]["R52"] = {"rc": rc, "verdict": parsed.get("verdict"), "reason": parsed.get("reason")}

    # ---- R53 prior-audit-finding-supersede ----
    rc, parsed, _ = _run_subprocess_json(
        R53,
        [str(draft_path), "--workspace", str(workspace), "--json"],
    )
    # R53 uses key "verdict" too.
    results["gates"]["R53"] = {"rc": rc, "verdict": parsed.get("verdict"), "reason": parsed.get("reason")}

    # ---- L31 duplicate-preflight ----
    rc, parsed, _ = _run_subprocess_json(
        L31,
        [str(draft_path), "--workspace", str(workspace), "--json"],
    )
    results["gates"]["L31"] = {"rc": rc, "verdict": parsed.get("verdict"), "reason": parsed.get("reason") or parsed.get("warnings")}

    # ---- Optional: pattern-migration-alert ----
    if PATTERN_MIGRATION.exists():
        rc, parsed, _ = _run_subprocess_json(
            PATTERN_MIGRATION,
            ["--workspace", str(workspace), "--candidate-id", str(candidate.get("candidate_id", "")), "--json"],
        )
        results["gates"]["pattern_migration"] = {
            "rc": rc,
            "verdict": parsed.get("verdict"),
            "matched_paid": bool(parsed.get("matched_paid_finding")),
            "reason": parsed.get("reason"),
        }
    else:
        results["gates"]["pattern_migration"] = {"status": "tool-absent", "matched_paid": False}

    # ---- Optional: scan-report-thicken ----
    if SCAN_REPORT_THICKEN.exists():
        rc, parsed, _ = _run_subprocess_json(
            SCAN_REPORT_THICKEN,
            ["--workspace", str(workspace), "--candidate-id", str(candidate.get("candidate_id", "")), "--json"],
        )
        results["gates"]["scan_report_thicken"] = {
            "rc": rc,
            "classifier_score": parsed.get("classifier_score"),
            "reason": parsed.get("reason"),
        }
    else:
        results["gates"]["scan_report_thicken"] = {"status": "tool-absent", "classifier_score": None}

    return results


def roll_up_verdict(gate_results: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Decide the candidate's hunt-verdict from the per-gate verdicts.

    Returns (verdict_label, reasons[]).
    Order of precedence:
      1. PAID-FINDING-MATCH-HIGH-PRIORITY  (if pattern_migration matched_paid)
      2. DESIGN-CHOICE-SKIP                (R45 says designed-as-intended)
      3. RUBRIC-NO-ROW-SKIP                (R52 fail-program-severity-missing-impact-class)
      4. LIKELY-DUPE-SKIP                  (L31 verdict != distinct, or R47 acknowledged-found)
      5. LIKELY-OOS-SKIP                   (R52 fail-no-rubric-row-cited is generic; ignore - synth-only;
                                            we ONLY count R52 if it actually finds 'no row' in SEVERITY.md.)
      6. HUNT-READY                        (default)
    """
    reasons: List[str] = []
    gates = gate_results.get("gates", {})

    pm = gates.get("pattern_migration") or {}
    if pm.get("matched_paid"):
        reasons.append("pattern-migration-alert: matched paid finding from prior engagement")
        return VERDICT_PAID_MATCH, reasons

    r45 = gates.get("R45") or {}
    if r45.get("verdict") == "fail-designed-as-intended-with-defense-in-depth":
        reasons.append(f"R45: {r45.get('reason') or 'designed-as-intended with defense-in-depth'}")
        return VERDICT_DESIGN_CHOICE_SKIP, reasons

    r52 = gates.get("R52") or {}
    # Only the program-missing-row verdict means RUBRIC-NO-ROW-SKIP. A
    # generic "no rubric row cited" verdict comes from the synthetic draft
    # not carrying the new Rubric Row Mapping section; that is hunt-time
    # noise, not a real signal.
    if r52.get("verdict") == "fail-program-severity-missing-impact-class":
        reasons.append(f"R52: {r52.get('reason') or 'program SEVERITY.md missing this impact class'}")
        return VERDICT_RUBRIC_NO_ROW_SKIP, reasons

    l31 = gates.get("L31") or {}
    # L31 returns "distinct" / "duplicate" / "manual-review-required" /
    # "rebuttal-accepted" plus underscore variants from the universal gate.
    # "no_priors_to_compare" is non-blocking at hunt-starter time.
    l31_v = l31.get("verdict")
    if l31_v and l31_v not in (
        "distinct",
        "distinct_by_uniqueness_escalation",
        "distinct_cross_asset",
        "no_priors_to_compare",
        "rebuttal-accepted",
        "rebuttal_accepted",
    ):
        reasons.append(f"L31: {l31_v}")
        return VERDICT_LIKELY_DUPE_SKIP, reasons

    r47 = gates.get("R47") or {}
    if r47.get("verdict") == "fail-acknowledged-without-extension-distinct":
        reasons.append(f"R47: {r47.get('reason') or 'team has acknowledged this; no extension-distinct evidence'}")
        return VERDICT_LIKELY_DUPE_SKIP, reasons

    r53 = gates.get("R53") or {}
    if r53.get("verdict") == "fail-superseded-by-prior-audit":
        reasons.append(f"R53: {r53.get('reason') or 'superseded by prior audit'}")
        return VERDICT_LIKELY_DUPE_SKIP, reasons

    # Default: hunt-ready.
    reasons.append("all preflight gates pass - dispatch a worker")
    return VERDICT_HUNT_READY, reasons


# ---------------------------------------------------------------------------
# Top-level driver.

def collect_candidates(workspace: Path, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Read engage_report.md + exploit_queue.json + mined_findings_obligations.json.

    Returns a deduplicated, severity-ranked list of candidates.
    """
    candidates: List[Dict[str, Any]] = []

    eng = workspace / "engage_report.md"
    if eng.exists():
        try:
            text = eng.read_text(encoding="utf-8", errors="replace")
            candidates.extend(parse_engage_report(text))
        except Exception as exc:
            candidates.append({
                "source": "engage_report.md",
                "candidate_id": "engage_report:parse-error",
                "error": str(exc),
                "severity_max": "LOW",
            })

    eq = workspace / ".auditooor" / "exploit_queue.json"
    if eq.exists():
        try:
            data = json.loads(eq.read_text(encoding="utf-8", errors="replace"))
            candidates.extend(parse_exploit_queue(data))
        except Exception as exc:
            candidates.append({
                "source": "exploit_queue.json",
                "candidate_id": "exploit_queue:parse-error",
                "error": str(exc),
                "severity_max": "MEDIUM",
            })

    smq = workspace / ".auditooor" / "exploit_queue.source_mined.json"
    if smq.exists():
        try:
            data = json.loads(smq.read_text(encoding="utf-8", errors="replace"))
            candidates.extend(parse_source_mined_queue(data))
        except Exception as exc:
            candidates.append({
                "source": "exploit_queue.source_mined.json",
                "candidate_id": "exploit_queue.source_mined:parse-error",
                "error": str(exc),
                "severity_max": "MEDIUM",
            })

    mob = workspace / ".auditooor" / "mined_findings_obligations.json"
    if mob.exists():
        try:
            data = json.loads(mob.read_text(encoding="utf-8", errors="replace"))
            candidates.extend(parse_mined_obligations(data))
        except Exception as exc:
            candidates.append({
                "source": "mined_findings_obligations.json",
                "candidate_id": "mined_findings_obligations:parse-error",
                "error": str(exc),
                "severity_max": "MEDIUM",
            })

    # Deduplicate by durable lead/title where possible. If the same lead exists
    # in exploit_queue.json and exploit_queue.source_mined.json, keep the
    # source-mined version because it carries source artifacts and impact
    # contract state.
    source_preference = {
        "exploit_queue.source_mined.json": 0,
        "exploit_queue.json": 1,
        "mined_findings_obligations.json": 2,
        "engage_report.md": 3,
    }
    deduped: Dict[str, Dict[str, Any]] = {}
    for cand in candidates:
        key = str(cand.get("lead_id") or cand.get("candidate_id") or cand.get("title") or "").strip()
        if not key:
            key = str(cand)
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = cand
            continue
        old_pref = source_preference.get(str(existing.get("source")), 99)
        new_pref = source_preference.get(str(cand.get("source")), 99)
        if new_pref < old_pref:
            deduped[key] = cand
    candidates = list(deduped.values())

    # Severity-rank: CRITICAL > HIGH > MEDIUM > LOW for deterministic ordering.
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    candidates.sort(key=lambda c: (sev_order.get((c.get("severity_max") or "LOW").upper(), 9), c.get("candidate_id", "")))

    if limit is not None and limit > 0:
        candidates = candidates[:limit]

    return candidates


def emit_markdown_report(
    workspace: Path,
    candidates: List[Dict[str, Any]],
    verdicts: List[Dict[str, Any]],
    generated_at: str,
) -> str:
    """Build the human-readable markdown summary."""
    by_v: Dict[str, int] = {}
    for v in verdicts:
        by_v[v["verdict"]] = by_v.get(v["verdict"], 0) + 1

    lines: List[str] = []
    lines.append(f"# Hunt-Starter Ranked Candidates")
    lines.append("")
    lines.append(f"- Workspace: `{workspace}`")
    lines.append(f"- Generated: {generated_at}")
    lines.append(f"- Total candidates pre-screened: **{len(verdicts)}**")
    lines.append(f"- Schema: `{SCHEMA}`")
    lines.append("")
    lines.append("## Verdict distribution")
    lines.append("")
    for v in VERDICT_PRIORITY:
        if v in by_v:
            lines.append(f"- **{v}**: {by_v[v]}")
    lines.append("")
    lines.append("## Per-candidate verdicts")
    lines.append("")
    lines.append("| candidate_id | source | severity | verdict | P1 invariants | P3 patterns | live target | impact contract | reason |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for v in verdicts:
        reason_short = "; ".join(v.get("reasons") or [])[:160].replace("|", "\\|").replace("\n", " ")
        p1s = v.get("matched_p1_invariants") or []
        p3s = v.get("matched_p3_patterns") or []
        p1_cell = ", ".join(p1s[:3]) + (f" (+{len(p1s)-3})" if len(p1s) > 3 else "") if p1s else "-"
        p3_cell = ", ".join(p3s[:3]) + (f" (+{len(p3s)-3})" if len(p3s) > 3 else "") if p3s else "-"
        live = v.get("live_target_context") or {}
        live_cell = live.get("hunt_priority") or "-"
        impact_cell = v.get("impact_contract_status") or "-"
        if v.get("impact_contract_id"):
            impact_cell = f"{impact_cell} `{v.get('impact_contract_id')}`"
        lines.append(
            f"| `{v['candidate_id']}` | {v.get('source') or '-'} | {v.get('severity_max') or 'LOW'} | {v['verdict']} | "
            f"{p1_cell} | {p3_cell} | {live_cell} | {impact_cell} | {reason_short} |"
        )
    lines.append("")
    lines.append("## Next steps")
    lines.append("")
    lines.append("- `HUNT-READY-RICH-CONTEXT` candidates have P1+P3 composability backing - dispatch a worker first.")
    lines.append("- `HUNT-READY` candidates are eligible for worker dispatch.")
    lines.append("- `*-SKIP` candidates should NOT be dispatched without operator override + rebuttal.")
    lines.append("- `PAID-FINDING-MATCH-HIGH-PRIORITY` candidates jump the queue.")
    lines.append("")
    return "\n".join(lines)


def run(
    workspace: Path,
    limit: Optional[int] = None,
    emit_files: bool = True,
) -> Dict[str, Any]:
    """Top-level entry. Returns the JSON envelope; optionally writes files.

    P1/P3 enrichment (WIRING-1 lane): each verdict row is annotated with
    ``matched_p1_invariants: [...]`` + ``matched_p3_patterns: [...]`` based
    on the candidate's detector cluster slug. HUNT-READY rows that meet
    ``HUNT_READY_RICH_MIN_P1`` + ``HUNT_READY_RICH_MIN_P3`` are promoted to
    the HUNT-READY-RICH-CONTEXT verdict bucket. Pilot-audited P1 subset
    is preferred over the full library when ``invariants_pilot_audited.jsonl``
    is present.
    """
    generated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # P1/P3 catalogs loaded once per run. Empty index when neither source
    # is present - matching falls back cleanly to empty lists.
    p1_index, p1_source = load_p1_invariants()
    p3_index = load_p3_patterns()
    live_index, live_source = load_live_target_context(workspace)

    candidates = collect_candidates(workspace, limit=limit)
    verdicts: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="hunt_starter_") as td:
        tmpdir = Path(td)

        def _process_candidate(cand: Dict[str, Any]) -> Dict[str, Any]:
            # Skip parse-error rows - they have no draftable content.
            if cand.get("error"):
                return {
                    "candidate_id": cand.get("candidate_id"),
                    "severity_max": cand.get("severity_max"),
                    "source": cand.get("source"),
                    "verdict": VERDICT_LIKELY_OOS_SKIP,
                    "reasons": [f"parse-error: {cand.get('error')}"],
                    "gates": {},
                    "matched_p1_invariants": [],
                    "matched_p3_patterns": [],
                    "live_target_context": {},
                    "impact_contract_id": cand.get("impact_contract_id") or "",
                    "impact_contract_status": cand.get("impact_contract_status") or "",
                    "impact_contract_gaps": cand.get("impact_contract_gaps") or [],
                }
            # Fast-path candidates with no usable rubric severity (e.g. a raw
            # source-mined grep hit). The rubric/design gates need an assessable
            # severity; without one they uniformly return a no-row skip, so
            # spending ~7 gate subprocesses on each is pure waste. A noisy
            # source_mined queue (seen at 21k UNKNOWN-severity rows) would
            # otherwise serialize the whole sweep into hours. The candidate still
            # gets a verdict row, so candidate/verdict accounting is unchanged.
            _sev = (cand.get("severity_max") or "").strip().upper()
            if _sev in ("", "UNKNOWN", "NONE", "INFO", "INFORMATIONAL"):
                return {
                    "candidate_id": cand.get("candidate_id"),
                    "severity_max": cand.get("severity_max"),
                    "source": cand.get("source"),
                    "title": cand.get("title") or cand.get("detector"),
                    "verdict": VERDICT_NO_SEVERITY_SKIP,
                    "reasons": [
                        "no rubric severity (raw source-mined / untriaged): "
                        "excluded from the gate sweep - assign a SEVERITY.md "
                        "severity to promote it into gating"
                    ],
                    "gates": {},
                    "matched_p1_invariants": [],
                    "matched_p3_patterns": [],
                    "live_target_context": {},
                    "source_artifact_path": cand.get("source_artifact_path") or "",
                    "source_artifacts_complete": bool(cand.get("source_artifacts_complete")),
                    "proof_status": cand.get("proof_status") or "",
                    "quality_gate_status": cand.get("quality_gate_status") or "",
                    "learning_route": cand.get("learning_route") or "",
                    "impact_contract_id": cand.get("impact_contract_id") or "",
                    "impact_contract_status": cand.get("impact_contract_status") or "",
                    "impact_contract_gaps": cand.get("impact_contract_gaps") or [],
                    "listed_impact_selected": cand.get("listed_impact_selected") or "",
                    "listed_impact_proven": bool(cand.get("listed_impact_proven")),
                }
            gate_results = run_gates(cand, workspace, tmpdir)
            verdict_label, reasons = roll_up_verdict(gate_results)

            # P1/P3 enrichment.
            matched_p1 = match_p1_for_candidate(cand, p1_index)
            matched_p3 = match_p3_for_candidate(cand, p3_index)
            live_context = match_live_target_for_candidate(cand, live_index)
            if live_context:
                live_p1 = live_context.get("matched_p1_invariants") or []
                live_p3 = live_context.get("matched_anti_patterns") or []
                matched_p1 = list(dict.fromkeys([*matched_p1, *[str(x) for x in live_p1]]))[:5]
                matched_p3 = list(dict.fromkeys([*matched_p3, *[str(x) for x in live_p3]]))
                reasons.append(
                    f"P5 live-target context: {live_context.get('hunt_priority') or 'ranked'}"
                )

            # Rich-context promotion: only HUNT-READY rows are eligible; a
            # SKIP-class verdict already encodes a stronger signal. P3 hits
            # that are "no-P3-match:*" sentinels do NOT count toward the
            # promotion threshold.
            real_p3 = [pid for pid in matched_p3 if not pid.startswith("no-P3-match:")]
            if (
                verdict_label == VERDICT_HUNT_READY
                and len(matched_p1) >= HUNT_READY_RICH_MIN_P1
                and len(real_p3) >= HUNT_READY_RICH_MIN_P3
            ):
                verdict_label = VERDICT_HUNT_READY_RICH_CONTEXT
                reasons.append(
                    f"P1+P3 composability: {len(matched_p1)} invariants + {len(real_p3)} patterns matched"
                )

            return {
                "candidate_id": cand.get("candidate_id"),
                "severity_max": cand.get("severity_max"),
                "source": cand.get("source"),
                "title": cand.get("title") or cand.get("detector"),
                "verdict": verdict_label,
                "reasons": reasons,
                "gates": gate_results.get("gates", {}),
                "matched_p1_invariants": matched_p1,
                "matched_p3_patterns": matched_p3,
                "live_target_context": live_context,
                "source_artifact_path": cand.get("source_artifact_path") or "",
                "source_artifacts_complete": bool(cand.get("source_artifacts_complete")),
                "proof_status": cand.get("proof_status") or "",
                "quality_gate_status": cand.get("quality_gate_status") or "",
                "learning_route": cand.get("learning_route") or "",
                "impact_contract_id": cand.get("impact_contract_id") or "",
                "impact_contract_status": cand.get("impact_contract_status") or "",
                "impact_contract_gaps": cand.get("impact_contract_gaps") or [],
                "listed_impact_selected": cand.get("listed_impact_selected") or "",
                "listed_impact_proven": bool(cand.get("listed_impact_proven")),
            }

        # Each candidate runs ~7 gate subprocesses (R45/R47/R52/R53/L31 + 2
        # optional), so per-candidate work is subprocess/IO-bound and the GIL is
        # released while we wait. Fan out across candidates (generic + tunable
        # via AUDITOOOR_HUNT_STARTER_WORKERS, default min(16, cpu)) so a large
        # candidate set does not serialize into an O(N * 7 * subprocess) sweep
        # that blocks `make audit` (and thus the Step-2 deep engines). Verdict
        # order is preserved via executor.map; the gate work is read-only over
        # shared indexes and writes per-candidate-id draft files, so it is
        # thread-safe.
        if candidates:
            env_workers = int(os.environ.get("AUDITOOOR_HUNT_STARTER_WORKERS", "0") or "0")
            max_workers = env_workers if env_workers > 0 else min(16, (os.cpu_count() or 4))
            max_workers = max(1, min(max_workers, len(candidates)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                verdicts = list(executor.map(_process_candidate, candidates))

    envelope = {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "generated_at_utc": generated_at,
        "candidate_count": len(candidates),
        "verdict_count": len(verdicts),
        "verdicts": verdicts,
        "tool_versions": {
            "R45_present": R45.exists(),
            "R47_present": R47.exists(),
            "R52_present": R52.exists(),
            "R53_present": R53.exists(),
            "L31_present": L31.exists(),
            "pattern_migration_present": PATTERN_MIGRATION.exists(),
            "scan_report_thicken_present": SCAN_REPORT_THICKEN.exists(),
        },
        "p1_p3_compose": {
            "p1_source": p1_source,
            "p1_buckets": len(p1_index),
            "p3_buckets": len(p3_index),
            "rich_min_p1": HUNT_READY_RICH_MIN_P1,
            "rich_min_p3": HUNT_READY_RICH_MIN_P3,
        },
        "live_target_context": {
            "source": live_source,
            "path": str(workspace / LIVE_TARGET_REPORT_REL),
            "clusters": len(live_index),
        },
        "source_mined_context": {
            "candidate_count": sum(1 for c in candidates if c.get("source") == "exploit_queue.source_mined.json"),
            "with_impact_contract": sum(
                1 for c in candidates
                if c.get("source") == "exploit_queue.source_mined.json" and c.get("impact_contract_id")
            ),
        },
    }

    if emit_files:
        out_dir = workspace / ".auditooor"
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "hunt_candidates_ranked.json"
        md_path = out_dir / "hunt_candidates_ranked.md"
        json_path.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
        md_path.write_text(emit_markdown_report(workspace, candidates, verdicts, generated_at), encoding="utf-8")
        envelope["artifacts"] = {
            "json": str(json_path),
            "md": str(md_path),
        }

    return envelope


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="hunt-starter: R-rule pre-screening at hunt-time (WF-3 REC-1).")
    parser.add_argument("--workspace", "--ws", required=True, help="Path to audit workspace (e.g. ~/audits/dydx)")
    parser.add_argument("--limit", type=int, default=None, help="Max candidates to process (default: all)")
    parser.add_argument("--json", action="store_true", help="Emit JSON envelope on stdout")
    parser.add_argument("--no-write", action="store_true", help="Skip writing .auditooor/hunt_candidates_ranked.{json,md}")
    parser.add_argument("--if-stale-only", action="store_true",
                        help="Skip regeneration when .auditooor/hunt_candidates_ranked.json is fresh "
                             "(younger than --stale-ttl-min). Mirrors live-target-intel IF_STALE_ONLY: the "
                             "make-audit freshness path + audit-deep 'audit' prerequisite both re-invoke "
                             "hunt-starter, so this makes those no-ops when Step 1 just produced the artifact.")
    parser.add_argument("--stale-ttl-min", type=float, default=45.0,
                        help="Freshness window in minutes for --if-stale-only (default: 45).")
    args = parser.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[hunt-starter] ERR workspace not a directory: {ws}", file=sys.stderr)
        return 2

    # Freshness short-circuit: regenerating the ranked output is a full re-screen of
    # every exploit-queue candidate (thousands of rows on a large chain). When the
    # artifact is already fresh, that work is pure waste. --no-write has nothing to
    # protect, so the skip only applies to write-mode runs.
    if args.if_stale_only and not args.no_write:
        ranked = ws / ".auditooor" / "hunt_candidates_ranked.json"
        if ranked.is_file():
            age_min = (dt.datetime.now(dt.timezone.utc).timestamp() - ranked.stat().st_mtime) / 60.0
            if age_min < args.stale_ttl_min:
                if args.json:
                    print(json.dumps({"skipped": "fresh", "artifact": str(ranked),
                                      "age_min": round(age_min, 2), "ttl_min": args.stale_ttl_min}, indent=2))
                else:
                    print(f"[hunt-starter] skip-fresh: hunt_candidates_ranked.json is {age_min:.1f}min old "
                          f"(< {args.stale_ttl_min:.0f}min TTL); skipping regeneration "
                          f"(rerun without --if-stale-only to force).")
                return 0

    envelope = run(ws, limit=args.limit, emit_files=not args.no_write)

    if args.json:
        print(json.dumps(envelope, indent=2))
    else:
        n = envelope["verdict_count"]
        by_v: Dict[str, int] = {}
        for v in envelope["verdicts"]:
            by_v[v["verdict"]] = by_v.get(v["verdict"], 0) + 1
        print(f"[hunt-starter] processed {n} candidates")
        for v in VERDICT_PRIORITY:
            if v in by_v:
                print(f"  {v}: {by_v[v]}")
        if envelope.get("artifacts"):
            for k, p in envelope["artifacts"].items():
                print(f"  {k}: {p}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
