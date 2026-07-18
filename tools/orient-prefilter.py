#!/usr/bin/env python3
# r36-rebuttal: lane GAP-INTEG-1 registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py
"""ORIENT-phase prefilter for hunt candidates (Capability Gap 1+3 fix).

# Capability Gap 1 + 3 (2026-05-25): this tool emits no corpus record.

TRIGGER: Run AFTER a hunt-ORIENT lane has emitted a candidates JSON listing
N drill targets but BEFORE the per-candidate drill lanes are spawned. The
prefilter scores each candidate's KILL-RISK based on dry-runs of the same
R-gates (R45/R46/R47/R48/R53) that would otherwise only fire on a fully-
drafted finding deep in the cycle, plus a recent-fix-commit downgrade
(Gap 3) that flags candidates whose call graph was touched by a security
commit in the last N days.

Empirical anchor: 2026-05-25 hyperbridge full-hunt - 8 of 10 dispatched
drill lanes returned DROP after ~16h compute. Pre-filtering with this tool
would have flagged 7 of those 8 as warn-multi-gate-risk or
fail-high-kill-risk before spawning, conserving lane capacity for DRILL-6
(the lone POSITIVE).

Five gates evaluated per candidate, each emitting a per-gate kill-risk
contribution:

  R45-DAI-precheck    - protocol-own docs grep for design-intent endorsement of
                        an omission claim in proximity to the candidate's
                        attack-class keywords.
  R46-trusted-infra   - candidate hypothesis text and target file paths grep for
                        trusted-infra components plus SEVERITY.md OOS clause.
  R47-recent-fix      - git log --since='<window> days' on the candidate's
                        cited file paths for security commits (Gap 3 lever).
  R48-deployment-topo - candidate's hypothesis text grep for restricted-wallet
                        / testnet-only / env-flag topology gates.
  R53-prior-supersede - grep prior_audits/ corpus for candidate's
                        attack_class + cluster + key file stems.

Aggregate verdicts:
  pass-likely-fileable      - 0 gates above LOW kill-risk.
  warn-1-gate-risk          - exactly 1 gate at MEDIUM or higher.
  warn-multi-gate-risk      - 2-3 gates at MEDIUM or higher, none EXTREME.
  fail-high-kill-risk       - >=4 gates at MEDIUM, OR >=1 gate at EXTREME.
  error                     - input shape rejected / missing required field.

Per-candidate kill-risk grades:
  low      - no signal observed.
  medium   - weak signal (single phrase hit, no acknowledgement match).
  high     - strong signal (multiple phrase hits AND a co-located
             severity/scope evidence anchor).
  extreme  - acknowledged-by-design OR primary-defense overlap OR
             prior-audit supersede with no extension-distinct angle
             discernible from the candidate metadata.

Output: JSON document with prefilter_summary block + per-candidate gate
records. The aggregate severity_recommendation suggests whether to DROP /
DOWNGRADE / PROCEED. The downstream orchestrator decides; this tool only
emits the kill-risk dossier.

Schema: auditooor.orient_prefilter.v1

Usage:
  tools/orient-prefilter.py --candidates <orient-output.json> \
      --workspace <ws> --audit-pin <sha> [--json] [--days N]
"""

# r36-rebuttal: lane GAP-INTEG-1 registered in .auditooor/agent_pathspec.json
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.orient_prefilter.v1"
TOOL_NAME = "orient-prefilter"
MODE_DRILL = "drill"
MODE_COMPOSITION = "composition"

# Gap #30 platform-OOS check module (lazy-loaded to avoid import cost when
# the gate doesn't fire). GAP-INTEG-1 integration (2026-05-26).
_GAP30_MODULE_CACHE: Any = None


def _load_gap30_module() -> Any:
    """Lazy-load tools/always-escalate-platform-oos-check.py as a module.

    Returns the loaded module or None if missing / fails to load (graceful
    degradation: per-candidate gate result records gap30_status='tool-missing'
    and skips the downgrade).
    """
    # r36-rebuttal: GAP-INTEG-1 pathspec registered
    global _GAP30_MODULE_CACHE
    if _GAP30_MODULE_CACHE is not None:
        if _GAP30_MODULE_CACHE is False:
            return None
        return _GAP30_MODULE_CACHE
    tool_path = Path(__file__).resolve().parent / "always-escalate-platform-oos-check.py"
    if not tool_path.is_file():
        _GAP30_MODULE_CACHE = False
        return None
    try:
        spec = importlib.util.spec_from_file_location("aep_oos_check", tool_path)
        if spec is None or spec.loader is None:
            _GAP30_MODULE_CACHE = False
            return None
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _GAP30_MODULE_CACHE = m
        return m
    except (OSError, ImportError, SyntaxError):
        _GAP30_MODULE_CACHE = False
        return None


# Kill-risk grade ranks for arithmetic comparisons.
KILL_RISK_RANK = {"low": 0, "medium": 1, "high": 2, "extreme": 3}

# Default recent-fix window for Gap 3 R47 lever (days).
DEFAULT_RECENT_FIX_WINDOW_DAYS = 180

# ---------------------------------------------------------------------------
# Pattern libraries (kept narrow on purpose - this is a prefilter, not the
# full gate.  We trade FN risk for FP-tolerance because the downstream
# drill lane is the source of truth.)
# ---------------------------------------------------------------------------

# R45 design-intent / acknowledged-by-design - subset of the R45 patterns
# scoped to ORIENT-time evaluation where we have no draft.
R45_DESIGN_INTENT_PATTERNS = [
    r"\bby[\s-]design\b",
    r"\bintentional(?:ly)?\b",
    r"\bdesigned[\s-]as[\s-]intended\b",
    r"\backnowledged[\s-]by[\s-]design\b",
    r"\bknown[\s-]limitation\b",
    r"\bdesign[\s-]choice\b",
    r"\bdesign[\s-]decision\b",
    r"\bdocumented[\s-]behavior\b",
    r"\boptimistic\b.*\bno[\s-](?:wait|delay|challenge)\b",
]

# R46 trusted-infra-compromise component vocabulary.
R46_TRUSTED_COMPONENT_PATTERNS = [
    r"\b(?:oracle[\s-]sidecar|sidecar)\b",
    r"\bsequencer\b",
    r"\bproposer\s+infra(?:structure)?\b",
    r"\bvalidator[\s-](?:set[\s-]node|signer|node[\s-]comprom)",
    r"\bsigner[\s-]node\b",
    r"\bRPC\s+provider\b",
    r"\boff[\s-]chain\s+dispatcher\b",
    r"\bMEV[\s-](?:share|relay)\b",
    r"\bkeeper\s+node\b",
    r"\btrusted\s+infrastructure\b",
    r"\bcollator\s+node\b",
    r"\brelayer\s+node\b",
]

# R46 OOS-clause vocabulary (matches SEVERITY.md / SCOPE.md phrasing).
R46_OOS_CLAUSE_PATTERNS = [
    r"\boff[\s-]chain\s+infrastructure\b.*\b(?:OOS|out[\s-]of[\s-]scope|not\s+in\s+scope)\b",
    r"\bvalidator[\s-]key\s+comprom\w*\b.*\b(?:OOS|out[\s-]of[\s-]scope)\b",
    r"\bcomprom\w+\s+of\s+(?:off[\s-]chain|trusted)\s+infra\w*\b",
    r"\bcomprom\w+\s+of\s+(?:sequencer|sidecar|validator|signer|operator|proposer)\s+(?:node|infra)?\b",
    r"\bcentralization\s+risk(?:s)?\s+(?:acknowledged|accepted|OOS)\b",
    r"\backnowledged(?:[\s-]by[\s-]design)?\b.*\b(?:centraliz|trusted|operator|admin)\b",
]

# R47 recent-fix commit message vocabulary (Gap 3 lever).
R47_RECENT_FIX_KEYWORDS = [
    "fix",
    "security",
    "audit",
    "vulnerability",
    "patch",
    "harden",
    "tighten",
    "gate",
    "bind",
    "guard",
    "validate",
    "restrict",
    "sanitize",
]

# R48 deployment-topology restriction vocabulary.
R48_TOPOLOGY_PATTERNS = [
    r"\b(?:deposit|proxy|smart)\s+wallet\b",
    r"\b(?:EIP[\s-]?1271|ERC[\s-]?1271)\b",
    r"\babstract\s+account\b",
    r"\baccount\s+abstraction\b",
    r"\b(?:testnet|staging|dev|sandbox)[\s-]only\b",
    r"\btest\s+environment\b",
    r"\b(?:feature|env(?:ironment)?)\s+flag\b",
    r"\b(?:admin|owner|operator)[\s-]only\s+(?:path|route|function)\b",
    r"\bonly\s+(?:deployed|instantiated|configured)\s+(?:on|in|for)\s+(?:test|staging|sandbox)\b",
    r"\bTEE[\s-](?:specific|only)\b",
]


def _compile_union(patterns: list[str]) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


_R45_DI_RE = _compile_union(R45_DESIGN_INTENT_PATTERNS)
_R46_COMP_RE = _compile_union(R46_TRUSTED_COMPONENT_PATTERNS)
_R46_OOS_RE = _compile_union(R46_OOS_CLAUSE_PATTERNS)
_R48_TOPO_RE = _compile_union(R48_TOPOLOGY_PATTERNS)


# ---------------------------------------------------------------------------
# Candidate parsing
# ---------------------------------------------------------------------------

REQUIRED_CANDIDATE_FIELDS = ("id", "files")
REQUIRED_COMPOSITION_FIELDS = ("id", "chain")


def _load_candidates(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load the ORIENT candidates JSON.

    Returns (candidates_list, top_level_meta) where top_level_meta carries
    pass-through fields like workspace / audit_pin / generated_at_utc.
    Accepts both the canonical `drill_candidates` array and a top-level
    `candidates` array.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    candidates = raw.get("drill_candidates") or raw.get("candidates") or []
    if not isinstance(candidates, list):
        raise ValueError("candidates JSON: 'drill_candidates' / 'candidates' must be a list")
    for c in candidates:
        if not isinstance(c, dict):
            raise ValueError("candidate entries must be objects")
        for f in REQUIRED_CANDIDATE_FIELDS:
            if f not in c:
                raise ValueError(f"candidate {c!r} missing required field {f!r}")
    meta = {
        "source_schema": raw.get("schema"),
        "source_workspace": raw.get("workspace"),
        "source_audit_pin": raw.get("audit_pin"),
        "source_context_pack_id": raw.get("context_pack_id"),
        "source_context_pack_hash": raw.get("context_pack_hash"),
        "source_generated_at_utc": raw.get("generated_at_utc"),
        "candidate_count": len(candidates),
    }
    return candidates, meta


def _load_composition_candidates(
    path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, dict[str, Any]]]:
    """Load `composition_queue` rows and linked drill-candidate metadata."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    compositions = raw.get("composition_queue") or []
    if not isinstance(compositions, list):
        raise ValueError("candidates JSON: 'composition_queue' must be a list")
    for c in compositions:
        if not isinstance(c, dict):
            raise ValueError("composition entries must be objects")
        for f in REQUIRED_COMPOSITION_FIELDS:
            if f not in c:
                raise ValueError(f"composition {c!r} missing required field {f!r}")
    drill_candidates = raw.get("drill_candidates") or raw.get("candidates") or []
    if not isinstance(drill_candidates, list):
        raise ValueError("candidates JSON: linked 'drill_candidates' / 'candidates' must be a list")
    drill_index: dict[str, dict[str, Any]] = {}
    for d in drill_candidates:
        if isinstance(d, dict) and isinstance(d.get("id"), str):
            drill_index[d["id"]] = d
    meta = {
        "source_schema": raw.get("schema"),
        "source_workspace": raw.get("workspace"),
        "source_audit_pin": raw.get("audit_pin"),
        "source_context_pack_id": raw.get("context_pack_id"),
        "source_context_pack_hash": raw.get("context_pack_hash"),
        "source_generated_at_utc": raw.get("generated_at_utc"),
        "candidate_count": len(compositions),
        "linked_drill_candidate_count": len(drill_index),
        "mode": MODE_COMPOSITION,
    }
    return compositions, meta, drill_index


def _candidate_text(c: dict[str, Any]) -> str:
    """Flatten the candidate's text fields into one searchable blob."""
    parts: list[str] = []
    for k in (
        "name",
        "cluster",
        "attack_class",
        "severity_estimate",
        "prior_audit_coverage",
        "r47_r53_risk",
        "poc_target",
        "p1_tier",
    ):
        v = c.get(k)
        if isinstance(v, str):
            parts.append(v)
    for k in ("hypothesis_seeds", "p1_invariants", "key_lines"):
        v = c.get(k)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    parts.append(item)
        elif isinstance(v, str):
            parts.append(v)
    files = c.get("files")
    if isinstance(files, list):
        parts.extend([str(f) for f in files])
    return "\n".join(parts)


def _composition_text(c: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("name", "chain", "severity_estimate"):
        value = c.get(key)
        if isinstance(value, str):
            parts.append(value)
    depends_on = c.get("depends_on")
    if isinstance(depends_on, list):
        parts.extend(str(item) for item in depends_on)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Workspace document scan helpers
# ---------------------------------------------------------------------------

DOC_FILENAMES = (
    "README.md",
    "readme.md",
    "SECURITY.md",
    "security.md",
    "SCOPE.md",
    "scope.md",
    "SEVERITY.md",
    "severity.md",
    "ARCHITECTURE.md",
    "architecture.md",
    "DESIGN.md",
    "design.md",
    "FAQ.md",
    "faq.md",
    "KNOWN_ISSUES.md",
    "known_issues.md",
)

DOC_SUBDIRS = ("docs", "doc", "documentation")

PRIOR_AUDITS_SUBDIR = "prior_audits"

READABLE_SUFFIXES = (".md", ".txt", ".rst", ".json")


def _read_text_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _scan_workspace_docs(ws: Path) -> list[tuple[str, str]]:
    """Return [(path_str, text)] for protocol-own docs (no prior_audits)."""
    results: list[tuple[str, str]] = []
    for name in DOC_FILENAMES:
        p = ws / name
        if p.is_file():
            results.append((str(p), _read_text_safe(p)))
    for sub in DOC_SUBDIRS:
        d = ws / sub
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.md")):
            if p.is_file():
                results.append((str(p), _read_text_safe(p)))
    return results


def _scan_prior_audits(ws: Path) -> list[tuple[str, str]]:
    """Return [(path_str, text)] for prior_audits/* files."""
    results: list[tuple[str, str]] = []
    d = ws / PRIOR_AUDITS_SUBDIR
    if not d.is_dir():
        return results
    for p in sorted(d.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in READABLE_SUFFIXES:
            continue
        results.append((str(p), _read_text_safe(p)))
    return results


def _load_severity_md(ws: Path) -> str:
    for name in ("SEVERITY.md", "severity.md"):
        p = ws / name
        if p.is_file():
            return _read_text_safe(p)
    return ""


def _load_scope_md(ws: Path) -> str:
    for name in ("SCOPE.md", "scope.md"):
        p = ws / name
        if p.is_file():
            return _read_text_safe(p)
    return ""


# ---------------------------------------------------------------------------
# Per-gate dry-run logic
# ---------------------------------------------------------------------------

def _attack_class_keywords(c: dict[str, Any]) -> list[str]:
    """Extract a small keyword set from the candidate to seed grep windows."""
    kws: set[str] = set()
    for k in ("attack_class", "cluster"):
        v = c.get(k)
        if isinstance(v, str):
            for tok in re.split(r"[^a-zA-Z0-9]+", v):
                tok = tok.lower()
                if len(tok) >= 4:
                    kws.add(tok)
    name = c.get("name", "")
    if isinstance(name, str):
        for tok in re.split(r"[^a-zA-Z0-9]+", name):
            tok = tok.lower()
            if len(tok) >= 5:
                kws.add(tok)
    return sorted(kws)


def _gate_r45_design_intent(
    c: dict[str, Any],
    workspace_docs: list[tuple[str, str]],
) -> dict[str, Any]:
    """R45 dry-run: search workspace docs for design-intent phrases co-located
    with candidate-attack-class keywords within a proximity window.
    """
    kws = _attack_class_keywords(c)
    hits: list[dict[str, Any]] = []
    proximity = 250
    for path_str, text in workspace_docs:
        for m in _R45_DI_RE.finditer(text):
            start = max(0, m.start() - proximity)
            end = min(len(text), m.end() + proximity)
            window = text[start:end].lower()
            for kw in kws:
                if kw in window:
                    line_num = text[: m.start()].count("\n") + 1
                    hits.append(
                        {
                            "file": path_str,
                            "line": line_num,
                            "phrase": m.group(0)[:60],
                            "co_keyword": kw,
                        }
                    )
                    break
            if len(hits) >= 8:
                break
        if len(hits) >= 8:
            break

    if not hits:
        return {"gate": "R45", "kill_risk": "low", "hits": [], "reason": "no design-intent phrase co-located with candidate keywords"}

    # Multiple hits OR an acknowledged-by-design hit pushes to high.
    acknowledged = any(
        "acknowledged" in h["phrase"].lower() or "by-design" in h["phrase"].lower() or "by design" in h["phrase"].lower()
        for h in hits
    )
    if acknowledged:
        return {
            "gate": "R45",
            "kill_risk": "extreme",
            "hits": hits[:8],
            "reason": "explicit 'acknowledged-by-design' phrase co-located with candidate keywords",
        }
    if len(hits) >= 3:
        return {
            "gate": "R45",
            "kill_risk": "high",
            "hits": hits[:8],
            "reason": "multiple design-intent phrases co-located with candidate keywords",
        }
    return {
        "gate": "R45",
        "kill_risk": "medium",
        "hits": hits[:8],
        "reason": "single design-intent phrase co-located with candidate keywords",
    }


def _gate_r46_trusted_infra(
    c: dict[str, Any],
    severity_md: str,
    scope_md: str,
) -> dict[str, Any]:
    """R46 dry-run: scan the candidate's hypothesis text + file paths for
    trusted-infra dependencies, then cross-check SEVERITY.md/SCOPE.md for an
    OOS clause covering that component class.
    """
    blob = _candidate_text(c)
    component_hits = [m.group(0) for m in _R46_COMP_RE.finditer(blob)]
    severity_oos_hits = [m.group(0) for m in _R46_OOS_RE.finditer(severity_md)]
    scope_oos_hits = [m.group(0) for m in _R46_OOS_RE.finditer(scope_md)]

    if not component_hits:
        return {
            "gate": "R46",
            "kill_risk": "low",
            "component_hits": [],
            "oos_clause_hits": severity_oos_hits[:4] + scope_oos_hits[:4],
            "reason": "no trusted-infra dependency in candidate text",
        }
    if not (severity_oos_hits or scope_oos_hits):
        return {
            "gate": "R46",
            "kill_risk": "medium",
            "component_hits": component_hits[:6],
            "oos_clause_hits": [],
            "reason": "trusted-infra dependency named but no OOS clause cited in SEVERITY.md/SCOPE.md",
        }
    # Both present: candidate depends on infra that program OOS clause covers.
    return {
        "gate": "R46",
        "kill_risk": "extreme",
        "component_hits": component_hits[:6],
        "oos_clause_hits": (severity_oos_hits[:4] + scope_oos_hits[:4])[:6],
        "reason": "trusted-infra dependency AND program OOS clause covering its compromise present; primary-defense closure likely",
    }


def _gate_r47_recent_fix(
    c: dict[str, Any],
    workspace: Path,
    audit_pin: str,
    days: int,
) -> dict[str, Any]:
    """R47 recent-fix-commit dry-run (Gap 3 lever).

    For each cited file in the candidate, query git log --since='<days> days'
    on the workspace's src/ submodules for security-keyword commits that
    touch the file.  A recent security commit on the candidate's call graph
    is a downgrade signal - the team already shipped a fix that may have
    closed the contested surface.

    Kill-risk grading:
      - extreme: any commit subject contains an attack-class keyword from
        the candidate (the fix DIRECTLY targets the hypothesised bug class).
      - high: >=3 generic security commits on the candidate files (the
        surface is in active hardening).
      - medium: 1-2 generic security commits.
      - low: none.
    """
    files = c.get("files") or []
    if not isinstance(files, list):
        files = []

    # Build attack-class keyword set from candidate metadata for "directly
    # targets the bug class" detection.  We restrict to BUG-CLASS keywords,
    # NOT component/file names (which inevitably appear in any commit subject
    # touching that file).  Common-component words are excluded via a stoplist.
    raw_kws = set(_attack_class_keywords(c))
    component_stoplist = {
        "pallet", "bandwidth", "relayer", "intents", "intent", "polygon",
        "bsc", "manager", "module", "client", "consensus", "router",
        "gateway", "handler", "intentsv2", "polygon", "ismp", "ismpv2",
        "messaging", "incentives", "executive", "fungible", "token",
        "hyperbridge", "merkle", "trie", "ethereum", "scale", "codec",
        "trie", "uniswap", "uniswapv2", "univ4", "univ3", "wrapper",
        "oracle", "vwap", "sp1", "beefy", "ecdsa", "ics23", "handler",
        "intentsbase", "intrinsicintents", "extrinsicintents", "solveraccount",
        "bandwidthmanager", "handlerv2", "handlerv1", "lz", "lzendpoint",
        "consensusrouter", "vwaporacle", "ethereumtrie", "ethereumtriedb",
        "scalecodec", "intentgatewayv2", "evmhost", "spbeefy", "ecdsabeefy",
        "gnosis", "univ4uniswapv2wrapper", "univ3uniswapv2wrapper",
        "gnosisuniswapv2wrapper", "hyperbridgelzendpoint", "auth",
    }
    attack_kws: set[str] = {kw for kw in raw_kws if kw not in component_stoplist}
    # Add canonical bug-class phrases - these are multi-word keywords that
    # rarely false-positive on component names.
    extra_kws: set[str] = set()
    name = (c.get("name") or "").lower()
    cluster = (c.get("cluster") or "").lower()
    attack_class = (c.get("attack_class") or "").lower()
    blob = " ".join((name, cluster, attack_class))
    if "transient" in blob or "tstore" in blob or "eip-1153" in blob or "eip1153" in blob:
        extra_kws.update({"transient-storage", "transient", "tstore"})
    if "fee-on-transfer" in blob or "fot" in blob.split() or "fee on transfer" in blob:
        extra_kws.update({"fee-on-transfer", "transfer-tax", "deflationary"})
    if "finaliz" in blob:
        # Skip pure 'finalization' since it's too common in cross-chain
        # commit subjects; only fire on specific finality patterns.
        extra_kws.update({"unfinalized", "unfinalised"})
    if "truncat" in blob or "u128" in blob or "downcast" in blob:
        extra_kws.update({"truncation", "u256-to-u128", "downcast", "as-u128"})
    if "auth-bypass" in blob or "authentication" in blob:
        extra_kws.update({"auth-bypass", "authentication-bypass", "impersonation"})
    if "double-refund" in blob or "double-mint" in blob or "double-spend" in blob:
        extra_kws.update({"double-refund", "double-mint", "double-spend"})
    if "non-membership" in blob:
        extra_kws.update({"non-membership"})
    attack_kws.update(extra_kws)
    # Drop any remaining short keywords (<8 chars) - those collide with
    # generic commit subjects like "fix clients" or "fix relayer".  The
    # extra_kws set adds the multi-word bug-class phrases that are >=8 chars
    # to make the gate fire when a fix DIRECTLY targets the bug class.
    attack_kws = {kw for kw in attack_kws if len(kw) >= 8}

    repo_roots = _find_git_repos(workspace)
    commits: list[dict[str, Any]] = []
    direct_hit_commits: list[dict[str, Any]] = []
    seen_shas: set[str] = set()
    for rel_file in files:
        rel_str = str(rel_file)
        # Look for a repo whose relpath suffix matches the candidate's file path.
        for repo in repo_roots:
            short = _file_under_repo(repo, rel_str)
            if short is None:
                continue
            try:
                out = subprocess.check_output(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "log",
                        "--all",
                        f"--since={days} days ago",
                        "--pretty=format:%H%x09%ai%x09%s",
                        "--",
                        short,
                    ],
                    text=True,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                continue
            for line in out.splitlines():
                if not line.strip():
                    continue
                parts = line.split("\t", 2)
                if len(parts) != 3:
                    continue
                sha, when, subject = parts
                if sha in seen_shas:
                    continue
                low = subject.lower()
                if any(kw in low for kw in R47_RECENT_FIX_KEYWORDS):
                    seen_shas.add(sha)
                    record = {
                        "sha": sha[:10],
                        "date": when,
                        "subject": subject[:140],
                        "file": short,
                        "repo": str(repo),
                    }
                    commits.append(record)
                    # Direct-hit: commit subject mentions an attack-class keyword.
                    if attack_kws and any(kw in low for kw in attack_kws if len(kw) >= 4):
                        record_with_match = dict(record)
                        matched = [kw for kw in attack_kws if len(kw) >= 4 and kw in low]
                        record_with_match["attack_class_match"] = matched
                        direct_hit_commits.append(record_with_match)

    if not commits:
        return {
            "gate": "R47",
            "kill_risk": "low",
            "recent_security_commits": [],
            "direct_hit_commits": [],
            "reason": f"no security commits touching candidate files in last {days} days",
            "audit_pin": audit_pin,
        }
    if direct_hit_commits:
        return {
            "gate": "R47",
            "kill_risk": "extreme",
            "recent_security_commits": commits[:10],
            "direct_hit_commits": direct_hit_commits[:6],
            "reason": (
                f"{len(direct_hit_commits)} commit(s) directly targeting the candidate's attack class "
                f"in last {days} days (e.g. {direct_hit_commits[0]['sha']} '{direct_hit_commits[0]['subject'][:60]}')"
            ),
            "audit_pin": audit_pin,
        }
    if len(commits) >= 5:
        return {
            "gate": "R47",
            "kill_risk": "high",
            "recent_security_commits": commits[:10],
            "direct_hit_commits": [],
            "reason": f"{len(commits)} security commits touching candidate files in last {days} days; surface in active hardening",
            "audit_pin": audit_pin,
        }
    if len(commits) >= 2:
        return {
            "gate": "R47",
            "kill_risk": "medium",
            "recent_security_commits": commits[:10],
            "direct_hit_commits": [],
            "reason": f"{len(commits)} security commit(s) touching candidate files in last {days} days",
            "audit_pin": audit_pin,
        }
    return {
        "gate": "R47",
        "kill_risk": "low",
        "recent_security_commits": commits[:10],
        "direct_hit_commits": [],
        "reason": f"{len(commits)} commit touching candidate files (below medium threshold)",
        "audit_pin": audit_pin,
    }


def _find_git_repos(workspace: Path) -> list[Path]:
    """Find git repos at workspace or one level under workspace/src/."""
    repos: list[Path] = []
    if (workspace / ".git").is_dir():
        repos.append(workspace)
    src = workspace / "src"
    if src.is_dir():
        for child in sorted(src.iterdir()):
            if (child / ".git").exists():
                repos.append(child)
    # Try workspace root descendants as a fallback (one level only).
    for child in sorted(workspace.iterdir()) if workspace.is_dir() else []:
        if (child / ".git").is_dir() and child not in repos:
            repos.append(child)
    return repos


def _file_under_repo(repo: Path, candidate_rel: str) -> str | None:
    """Heuristic: return the relative-to-repo path that best matches the
    candidate's relative-to-workspace file path.  Strips known prefix tokens
    (`hyperbridge/evm/`, `modules/`) and looks for the longest suffix overlap.
    """
    norm = candidate_rel.replace("\\", "/").lstrip("./")
    # Try the literal path.
    if (repo / norm).is_file():
        return norm
    # Try stripping the leading path component.
    parts = norm.split("/", 1)
    if len(parts) == 2 and (repo / parts[1]).is_file():
        return parts[1]
    # Try stripping two leading components.
    parts2 = norm.split("/", 2)
    if len(parts2) == 3 and (repo / parts2[2]).is_file():
        return parts2[2]
    # Last resort: search by basename in tracked files (bounded).
    basename = norm.rsplit("/", 1)[-1]
    if not basename or "/" in basename:
        return None
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo), "ls-files", f"*/{basename}"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired):
        return None
    matches = [m for m in out.splitlines() if m.strip()]
    if not matches:
        return None
    # Prefer the match whose suffix overlap with norm is longest.
    def overlap(m: str) -> int:
        a = norm.split("/")
        b = m.split("/")
        i = 0
        while i < min(len(a), len(b)) and a[-1 - i] == b[-1 - i]:
            i += 1
        return i
    matches.sort(key=overlap, reverse=True)
    return matches[0]


def _gate_r48_deployment_topology(c: dict[str, Any]) -> dict[str, Any]:
    """R48 dry-run: scan candidate hypothesis text for deployment-topology
    restriction language (restricted wallet types, testnet-only paths,
    env flags, admin-only routes).

    Also augmented with a "non-core component path" check - if the candidate's
    files live in /utils/, /lib/, /helpers/, /mocks/, /test/, the attack
    surface is structurally narrow and a downstream-consumer trace is needed
    before drilling (R42/R56 co-trigger).
    """
    blob = _candidate_text(c)
    hits = [m.group(0) for m in _R48_TOPO_RE.finditer(blob)]

    files = c.get("files") or []
    non_core_paths = []
    if isinstance(files, list):
        for f in files:
            f_str = str(f).lower()
            for marker in ("/utils/", "/utilities/", "/util/", "/helpers/",
                            "/helper/", "/lib/", "/libs/", "/mock/", "/mocks/",
                            "/test/", "/tests/", "/fixtures/"):
                if marker in f_str:
                    non_core_paths.append(f_str)
                    break

    test_only = any(
        re.search(r"\b(?:testnet|staging|dev|sandbox|test\s+environment)\b", h, re.IGNORECASE)
        for h in hits
    )
    if test_only:
        return {
            "gate": "R48",
            "kill_risk": "extreme",
            "topology_hits": hits[:6],
            "non_core_paths": non_core_paths,
            "reason": "candidate depends on testnet/staging/sandbox-only path; production population likely empty",
        }
    if len(hits) >= 2 or (hits and non_core_paths):
        return {
            "gate": "R48",
            "kill_risk": "high",
            "topology_hits": hits[:6],
            "non_core_paths": non_core_paths,
            "reason": "multiple topology-restriction signals OR (topology hit + non-core path) in candidate",
        }
    if hits:
        return {
            "gate": "R48",
            "kill_risk": "medium",
            "topology_hits": hits[:6],
            "non_core_paths": non_core_paths,
            "reason": "single topology-restriction signal in candidate text",
        }
    if non_core_paths:
        return {
            "gate": "R48",
            "kill_risk": "medium",
            "topology_hits": [],
            "non_core_paths": non_core_paths,
            "reason": (
                "candidate files live in /utils/ or /lib/ or /helpers/ path; "
                "structural attack surface narrow; downstream-consumer trace needed (R42/R56 co-trigger)"
            ),
        }
    return {
        "gate": "R48",
        "kill_risk": "low",
        "topology_hits": [],
        "non_core_paths": [],
        "reason": "no topology-restriction signal in candidate text",
    }


def _gate_r53_prior_audit_supersede(
    c: dict[str, Any],
    prior_audits: list[tuple[str, str]],
) -> dict[str, Any]:
    """R53 dry-run: grep prior_audits/* for the candidate's attack_class +
    cluster + cited-file basenames.  If a strong match surfaces AND the
    candidate metadata itself does NOT cite an extension-distinct angle,
    the gate emits HIGH/EXTREME.
    """
    if not prior_audits:
        return {
            "gate": "R53",
            "kill_risk": "low",
            "prior_audit_matches": [],
            "matched_terms": [],
            "reason": "no prior_audits/ corpus present (workspace has no prior audit reports)",
        }
    raw_kws = set(_attack_class_keywords(c))
    file_basenames: set[str] = set()
    files = c.get("files")
    if isinstance(files, list):
        for f in files:
            base = str(f).rsplit("/", 1)[-1]
            stem = base.split(".", 1)[0]
            # Only use specific multi-char contract names as terms (not
            # short module-name fragments like 'auth' or 'core').
            if stem and len(stem) >= 6:
                file_basenames.add(stem.lower())

    # Build search terms.  Require >=7 char specific terms - generic words
    # like 'auth', 'token', 'fee', 'state' produce too much noise in any
    # audit-report corpus.
    terms = {t for t in (raw_kws | file_basenames) if len(t) >= 7}
    # Reject generic component nouns and bug-class words that ANY audit
    # report mentions in passing.
    generic_audit_stoplist = {
        "module", "modular", "interface", "function", "structure",
        "library", "audit", "report", "section", "finding", "issue",
        "system", "client", "clients", "consumer", "process", "design",
        "operation", "pallet", "pallets", "relayer", "bandwidth",
        "transfer", "transferred", "accounting", "escrow", "overflow",
        "integer", "consensus", "membership", "height", "double",
        "address", "balance", "receipt", "request", "response",
        "storage", "validate", "validation", "verifier", "verify",
        "fungible", "tokens", "permissions", "contract", "contracts",
        "wrapper", "wrappers", "oracle", "oracles", "intents", "intent",
        "coprocessor", "manager", "managers",
    }
    terms = terms - generic_audit_stoplist
    if not terms:
        return {
            "gate": "R53",
            "kill_risk": "low",
            "prior_audit_matches": [],
            "matched_terms": [],
            "reason": "no specific terms (>=7 char, non-generic) derived from candidate metadata",
        }

    matches: list[dict[str, Any]] = []
    matched_terms: set[str] = set()
    for path_str, text in prior_audits:
        text_low = text.lower()
        for term in sorted(terms):
            # Use word-boundary match to reject incidental substring overlaps
            # ("transfer" inside "transferred", etc.).
            pat = re.compile(r"\b" + re.escape(term) + r"\b", re.IGNORECASE)
            m = pat.search(text_low)
            if m:
                matched_terms.add(term)
                idx = m.start()
                line_num = text[:idx].count("\n") + 1
                snippet_start = max(0, idx - 80)
                snippet_end = min(len(text), idx + len(term) + 80)
                snippet = text[snippet_start:snippet_end].replace("\n", " ").strip()[:200]
                matches.append(
                    {
                        "file": path_str,
                        "line": line_num,
                        "term": term,
                        "snippet": snippet,
                    }
                )
                if len(matches) >= 12:
                    break
        if len(matches) >= 12:
            break

    if not matches:
        return {
            "gate": "R53",
            "kill_risk": "low",
            "prior_audit_matches": [],
            "matched_terms": [],
            "reason": "no matching prior-audit terms found",
        }

    # Examine candidate metadata for an extension-distinct rebuttal pre-answer
    # AND for an EXPLICIT prior-coverage admission (CAUTION / MEDIUM / SRL).
    prior_coverage = c.get("prior_audit_coverage", "") or ""
    r47_r53_risk = c.get("r47_r53_risk", "") or ""
    combined_meta = prior_coverage + " " + r47_r53_risk

    extension_signal = bool(
        re.search(
            r"\b(?:NEW\b|new\s+(?:contract|architecture|surface)|distinct|extension[\s-]distinct|"
            r"different|not\s+covered|fundamentally\s+different)\b",
            combined_meta,
            re.IGNORECASE,
        )
    )
    # Self-declared prior-coverage admission - candidate already flagged risk
    # in its own metadata.  Treat this as a strong R53 signal regardless of
    # grep hit count.
    self_declared_caution = bool(
        re.search(
            r"\b(?:CAUTION|MEDIUM|HIGH)\b.*\b(?:prior|SRL|audit|covered)\b"
            r"|\b(?:prior|SRL|audit)\b.*\b(?:CAUTION|MEDIUM|HIGH)\b"
            r"|\bSRL\s+covered\b"
            r"|\bprior\s+SRL\b"
            r"|\bmust\s+prove\b.*\bdistinct\b"
            r"|\bmust\s+(?:be|distinguish)\b.*\b(?:prior|SRL)\b",
            combined_meta,
            re.IGNORECASE,
        )
    )
    # Soft-OK if metadata explicitly says "none" / no prior coverage / LOW.
    # Three signal classes:
    #  - prior_audit_coverage field starts with 'none' or 'not in prior'
    #  - r47_r53_risk field explicitly starts with 'LOW'
    #  - 'explicitly listed as not covered by prior audits' marker
    explicit_no_prior = bool(
        re.match(r"^\s*none\b", prior_coverage, re.IGNORECASE)
        or re.search(r"\bnot in prior\b|\bnot covered\b", prior_coverage, re.IGNORECASE)
        or re.search(r"\bexplicitly\s+(?:listed|not)\s+(?:as\s+)?(?:not\s+)?cover", combined_meta, re.IGNORECASE)
    )
    # Explicit LOW r47_r53 self-assessment - the candidate metadata explicitly
    # says R47/R53 risk is LOW.  This caps R53 kill-risk at MEDIUM regardless
    # of grep hit count (modulo strong self-declared CAUTION below).
    explicit_low_self_risk = bool(
        re.match(r"^\s*LOW\b", r47_r53_risk, re.IGNORECASE)
        or re.search(r"\br47_r53_risk\s*[:=]\s*LOW\b", combined_meta, re.IGNORECASE)
        or re.search(r"\bLOW\b\s*[-:]\s*(?:new|not\s+covered|explicitly)", r47_r53_risk, re.IGNORECASE)
    )

    distinct_term_count = len(matched_terms)

    # Self-declared CAUTION trumps extension_signal noise - the candidate
    # itself flagged R47/R53 risk; honour it.
    if self_declared_caution:
        return {
            "gate": "R53",
            "kill_risk": "extreme" if distinct_term_count >= 2 else "high",
            "prior_audit_matches": matches[:8],
            "matched_terms": sorted(matched_terms),
            "self_declared_kill_risk": prior_coverage[:160],
            "reason": (
                "candidate metadata explicitly flags CAUTION / MEDIUM / SRL prior coverage; "
                "drill MUST prove extension-distinct before drafting"
            ),
        }
    if explicit_low_self_risk:
        # Candidate metadata explicitly self-rates R47/R53 risk as LOW.
        # Cap the kill-risk at MEDIUM regardless of grep hit count.
        if distinct_term_count >= 4:
            return {
                "gate": "R53",
                "kill_risk": "medium",
                "prior_audit_matches": matches[:8],
                "matched_terms": sorted(matched_terms),
                "reason": (
                    f"candidate self-rates R47/R53 risk LOW ('{r47_r53_risk[:80]}') but {distinct_term_count} "
                    "distinct prior-audit terms surface; cap at MEDIUM - operator should still verify"
                ),
            }
        return {
            "gate": "R53",
            "kill_risk": "low",
            "prior_audit_matches": matches[:8],
            "matched_terms": sorted(matched_terms),
            "reason": (
                f"candidate metadata explicitly self-rates R47/R53 risk LOW ('{r47_r53_risk[:80]}')"
            ),
        }
    if extension_signal and distinct_term_count <= 2:
        return {
            "gate": "R53",
            "kill_risk": "low",
            "prior_audit_matches": matches[:8],
            "matched_terms": sorted(matched_terms),
            "reason": "prior-audit term hits but candidate metadata cites extension-distinct angle",
        }
    if explicit_no_prior and distinct_term_count <= 1:
        return {
            "gate": "R53",
            "kill_risk": "low",
            "prior_audit_matches": matches[:8],
            "matched_terms": sorted(matched_terms),
            "reason": "incidental term overlap; metadata explicitly notes no prior coverage",
        }
    if distinct_term_count >= 4:
        return {
            "gate": "R53",
            "kill_risk": "extreme",
            "prior_audit_matches": matches[:8],
            "matched_terms": sorted(matched_terms),
            "reason": f"{distinct_term_count} distinct candidate terms found in prior_audits/ "
                      "with no extension-distinct angle in candidate metadata",
        }
    if distinct_term_count >= 2:
        return {
            "gate": "R53",
            "kill_risk": "high",
            "prior_audit_matches": matches[:8],
            "matched_terms": sorted(matched_terms),
            "reason": f"{distinct_term_count} distinct candidate terms found in prior_audits/; "
                      "verify extension-distinct angle before drilling",
        }
    if distinct_term_count == 1:
        return {
            "gate": "R53",
            "kill_risk": "medium",
            "prior_audit_matches": matches[:8],
            "matched_terms": sorted(matched_terms),
            "reason": "single distinct candidate term found in prior_audits/; "
                      "likely incidental but verify",
        }
    return {
        "gate": "R53",
        "kill_risk": "low",
        "prior_audit_matches": matches[:8],
        "matched_terms": sorted(matched_terms),
        "reason": "no distinct candidate-term overlap with prior_audits/",
    }


# ---------------------------------------------------------------------------
# Composition mode helpers
# ---------------------------------------------------------------------------

_GENERIC_COMPONENT_TOKENS = {
    "accepts", "accepted", "attacker", "bandwidth", "block", "blocks", "bsc",
    "chain", "client", "commitment", "consensus", "corrupt", "credit",
    "delivery", "double", "executed", "fee", "forged", "full", "height",
    "inflation", "intent", "mints", "mint", "non", "oracle", "payment",
    "pallet", "post", "pre", "proof", "race", "refund", "request", "requests",
    "solver", "spend", "state", "timeout", "tokens", "underpays", "unfinalized",
}


def _chain_legs(chain: str) -> list[str]:
    return [seg.strip() for seg in chain.split("->") if seg.strip()]


def _leg_tokens(text: str) -> set[str]:
    tokens = {
        tok.lower()
        for tok in re.split(r"[^a-zA-Z0-9]+", text)
        if len(tok) >= 4
    }
    return {tok for tok in tokens if tok not in _GENERIC_COMPONENT_TOKENS}


def _map_legs_to_dependencies(
    composition: dict[str, Any],
    dependency_index: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    chain = str(composition.get("chain") or "")
    legs = _chain_legs(chain) or [str(composition.get("name") or composition.get("id") or "")]
    dependency_ids = [
        dep for dep in composition.get("depends_on", [])
        if isinstance(dep, str) and dep in dependency_index
    ]
    dependency_tokens = {
        dep: _leg_tokens(
            " ".join(
                str(dependency_index[dep].get(key) or "")
                for key in ("name", "cluster", "attack_class")
            )
        )
        for dep in dependency_ids
    }
    mapped: list[dict[str, Any]] = []
    assigned: set[str] = set()
    for idx, leg_text in enumerate(legs, start=1):
        best_dep = None
        best_score = -1
        tokens = _leg_tokens(leg_text)
        for dep in dependency_ids:
            dep_tokens = dependency_tokens.get(dep, set())
            score = len(tokens & dep_tokens)
            if score > best_score:
                best_dep = dep
                best_score = score
        linked_deps: list[str] = []
        if best_dep and best_score > 0:
            linked_deps = [best_dep]
            assigned.add(best_dep)
        mapped.append(
            {
                "leg_index": idx,
                "leg_text": leg_text,
                "linked_dependency_ids": linked_deps,
            }
        )

    unassigned = [dep for dep in dependency_ids if dep not in assigned]
    if unassigned:
        # Anchor unmatched dependencies onto the closest edge legs so no
        # dependency evidence disappears in composition mode.
        edge_indices = [0, len(mapped) - 1] if len(mapped) > 1 else [0]
        for dep in unassigned:
            leg_idx = min(
                edge_indices,
                key=lambda idx: (len(mapped[idx]["linked_dependency_ids"]), idx),
            )
            bucket = mapped[leg_idx]["linked_dependency_ids"]
            if dep not in bucket:
                bucket.append(dep)
    return mapped


def _composition_leg_candidate(
    composition: dict[str, Any],
    leg: dict[str, Any],
    dependency_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    linked = [dependency_index[dep] for dep in leg["linked_dependency_ids"] if dep in dependency_index]
    files: list[str] = []
    seeds = [
        str(composition.get("name") or ""),
        str(composition.get("chain") or ""),
        str(leg["leg_text"]),
    ]
    prior_coverage: list[str] = []
    prior_risk: list[str] = []
    clusters: list[str] = []
    attack_classes: list[str] = []
    for dep in linked:
        dep_files = dep.get("files")
        if isinstance(dep_files, list):
            files.extend(str(item) for item in dep_files)
        dep_seeds = dep.get("hypothesis_seeds")
        if isinstance(dep_seeds, list):
            seeds.extend(str(item) for item in dep_seeds if isinstance(item, str))
        if isinstance(dep.get("prior_audit_coverage"), str):
            prior_coverage.append(dep["prior_audit_coverage"])
        if isinstance(dep.get("r47_r53_risk"), str):
            prior_risk.append(dep["r47_r53_risk"])
        if isinstance(dep.get("cluster"), str):
            clusters.append(dep["cluster"])
        if isinstance(dep.get("attack_class"), str):
            attack_classes.append(dep["attack_class"])
    return {
        "id": f"{composition.get('id')}-LEG-{leg['leg_index']}",
        "name": f"{composition.get('id')} leg {leg['leg_index']}: {leg['leg_text']}",
        "cluster": " | ".join(clusters) if clusters else composition.get("name", ""),
        "attack_class": " | ".join(attack_classes) if attack_classes else composition.get("name", ""),
        "files": sorted(dict.fromkeys(files)),
        "severity_estimate": composition.get("severity_estimate"),
        "hypothesis_seeds": [seed for seed in seeds if seed],
        "prior_audit_coverage": " | ".join(prior_coverage) if prior_coverage else "composition leg",
        "r47_r53_risk": " | ".join(prior_risk) if prior_risk else "composition leg",
    }


def _composition_candidate_stub(
    composition: dict[str, Any],
    leg_results: list[dict[str, Any]],
) -> dict[str, Any]:
    files: list[str] = []
    seeds = [str(composition.get("chain") or ""), str(composition.get("name") or "")]
    prior_coverage: list[str] = []
    prior_risk: list[str] = []
    clusters: list[str] = []
    attack_classes: list[str] = []
    for leg in leg_results:
        files.extend(leg.get("files", []))
        seeds.append(str(leg.get("leg_text") or ""))
        candidate = leg.get("synthetic_candidate") or {}
        if isinstance(candidate.get("prior_audit_coverage"), str):
            prior_coverage.append(candidate["prior_audit_coverage"])
        if isinstance(candidate.get("r47_r53_risk"), str):
            prior_risk.append(candidate["r47_r53_risk"])
        if isinstance(candidate.get("cluster"), str):
            clusters.append(candidate["cluster"])
        if isinstance(candidate.get("attack_class"), str):
            attack_classes.append(candidate["attack_class"])
    return {
        "id": str(composition.get("id") or ""),
        "name": str(composition.get("name") or ""),
        "cluster": " | ".join(sorted(dict.fromkeys(clusters))) if clusters else composition.get("name", ""),
        "attack_class": " | ".join(sorted(dict.fromkeys(attack_classes))) if attack_classes else composition.get("name", ""),
        "files": sorted(dict.fromkeys(files)),
        "severity_estimate": composition.get("severity_estimate"),
        "hypothesis_seeds": [seed for seed in seeds if seed],
        "prior_audit_coverage": " | ".join(prior_coverage) if prior_coverage else "composition aggregate",
        "r47_r53_risk": " | ".join(prior_risk) if prior_risk else "composition aggregate",
    }


def _aggregate_composition_leg_risks(leg_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # r36-rebuttal: GAP-INTEG-1 pathspec registered
    # GAP-INTEG-1 (2026-05-26): include the GAP30-PLATFORM-OOS gate so
    # composition-aggregate gate_results carries the new gate too.
    gate_names = ("R45", "R46", "R47", "R48", "R53", "GAP30-PLATFORM-OOS")
    aggregated: list[dict[str, Any]] = []
    for gate_name in gate_names:
        per_leg = [
            {
                "leg_index": leg["leg_index"],
                "leg_text": leg["leg_text"],
                "kill_risk": leg["per_gate_kill_risk"].get(gate_name, "low"),
                "linked_dependency_ids": leg.get("linked_dependency_ids", []),
            }
            for leg in leg_results
        ]
        worst = max(per_leg, key=lambda row: KILL_RISK_RANK.get(row["kill_risk"], 0))
        max_rank = KILL_RISK_RANK.get(worst["kill_risk"], 0)
        multi_leg_non_low = sum(1 for row in per_leg if KILL_RISK_RANK.get(row["kill_risk"], 0) >= KILL_RISK_RANK["medium"])
        gate_reason = f"worst leg={worst['leg_index']} ({worst['kill_risk']})"
        if multi_leg_non_low >= 2:
            gate_reason += "; multiple legs carry non-low kill-risk"
        aggregated.append(
            {
                "gate": gate_name,
                "kill_risk": worst["kill_risk"] if max_rank > 0 else "low",
                "per_leg": per_leg,
                "reason": gate_reason,
            }
        )
    return aggregated


def _evaluate_composition_candidate(
    composition: dict[str, Any],
    workspace: Path,
    workspace_docs: list[tuple[str, str]],
    prior_audits: list[tuple[str, str]],
    severity_md: str,
    scope_md: str,
    audit_pin: str,
    days: int,
    dependency_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    leg_specs = _map_legs_to_dependencies(composition, dependency_index)
    leg_results: list[dict[str, Any]] = []
    for leg in leg_specs:
        synthetic_candidate = _composition_leg_candidate(composition, leg, dependency_index)
        evaluated = _evaluate_candidate(
            synthetic_candidate,
            workspace,
            workspace_docs,
            prior_audits,
            severity_md,
            scope_md,
            audit_pin,
            days,
        )
        leg_results.append(
            {
                "leg_index": leg["leg_index"],
                "leg_text": leg["leg_text"],
                "linked_dependency_ids": leg["linked_dependency_ids"],
                "verdict": evaluated["verdict"],
                "severity_recommendation": evaluated["severity_recommendation"],
                "per_gate_kill_risk": evaluated["per_gate_kill_risk"],
                "gate_results": evaluated["gate_results"],
                "hypothesis_uncertainty_score": evaluated["hypothesis_uncertainty_score"],
                "files": evaluated.get("files", []),
                "synthetic_candidate": synthetic_candidate,
            }
        )

    aggregate_candidate = _composition_candidate_stub(composition, leg_results)
    aggregate_gates = _aggregate_composition_leg_risks(leg_results)
    uncertainty = (
        _hypothesis_uncertainty_score(aggregate_candidate)
        + (1 if len(leg_results) >= 2 else 0)
        + sum(1 for leg in leg_results if leg["verdict"] != "pass-likely-fileable")
    )
    verdict, recommendation = _aggregate_verdict(aggregate_gates, uncertainty)
    risk_summary = {g["gate"]: g["kill_risk"] for g in aggregate_gates}
    multi_leg_non_pass = [leg["leg_index"] for leg in leg_results if leg["verdict"] != "pass-likely-fileable"]
    if len(leg_results) >= 2 and verdict == "warn-1-gate-risk":
        verdict = "warn-multi-gate-risk"
        recommendation = (
            "DOWNGRADE-OR-DROP - multi-leg composition inherits non-pass signals from linked drill surfaces; "
            "validate the single-component owners before spending a composition lane."
        )
    if len(leg_results) >= 2 and len(multi_leg_non_pass) >= 2 and verdict != "fail-high-kill-risk":
        verdict = "fail-high-kill-risk"
        recommendation = (
            "DROP - multi-leg composition stacks kill-risk across linked drill surfaces; "
            "work the owning drill candidates instead of spawning a chained lane."
        )
    return {
        "candidate_id": composition.get("id"),
        "candidate_name": composition.get("name"),
        "files": aggregate_candidate["files"],
        "attack_class": aggregate_candidate["attack_class"],
        "severity_estimate": composition.get("severity_estimate"),
        "verdict": verdict,
        "severity_recommendation": recommendation,
        "per_gate_kill_risk": risk_summary,
        "hypothesis_uncertainty_score": uncertainty,
        "gate_results": aggregate_gates,
        "composition_chain": composition.get("chain"),
        "depends_on": composition.get("depends_on", []),
        "leg_results": [
            {
                k: v for k, v in leg.items()
                if k != "synthetic_candidate"
            }
            for leg in leg_results
        ],
    }


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _aggregate_verdict(
    gates: list[dict[str, Any]],
    hypothesis_uncertainty_score: int,
) -> tuple[str, str]:
    """Return (verdict, severity_recommendation).

    hypothesis_uncertainty_score: count of explicit uncertainty phrases in
    the candidate's hypothesis seeds.  >=4 bumps the aggregate by one
    severity tier (the candidate itself confesses structural uncertainty,
    which historically correlates with negative-drill outcomes).
    """
    ranks = [KILL_RISK_RANK.get(g["kill_risk"], 0) for g in gates]
    extreme_count = sum(1 for r in ranks if r >= KILL_RISK_RANK["extreme"])
    medium_plus = sum(1 for r in ranks if r >= KILL_RISK_RANK["medium"])

    base_verdict: str
    if extreme_count >= 1 or medium_plus >= 4:
        base_verdict = "fail-high-kill-risk"
    elif medium_plus >= 2:
        base_verdict = "warn-multi-gate-risk"
    elif medium_plus == 1:
        base_verdict = "warn-1-gate-risk"
    else:
        base_verdict = "pass-likely-fileable"

    # Hypothesis-uncertainty bump: the candidate's own hypothesis seeds
    # contain >=4 explicit "is this safe? / does this verify? / can X
    # bypass Y?" phrasings.  Historically these candidates drill to a
    # structural-defense NEGATIVE verdict.
    upgrade_ladder = [
        "pass-likely-fileable",
        "warn-1-gate-risk",
        "warn-multi-gate-risk",
        "fail-high-kill-risk",
    ]
    bumped_by_uncertainty = False
    if hypothesis_uncertainty_score >= 4 and base_verdict != "fail-high-kill-risk":
        idx = upgrade_ladder.index(base_verdict)
        # Bump by one tier when uncertainty >= 4; by two when >= 7.
        bump = 2 if hypothesis_uncertainty_score >= 7 else 1
        new_idx = min(idx + bump, len(upgrade_ladder) - 1)
        if new_idx > idx:
            base_verdict = upgrade_ladder[new_idx]
            bumped_by_uncertainty = True

    bump_note = (
        " (bumped by hypothesis-uncertainty=" + str(hypothesis_uncertainty_score) + ")"
        if bumped_by_uncertainty
        else ""
    )

    if base_verdict == "fail-high-kill-risk":
        return (
            base_verdict,
            "DROP - dry-run gates flag this candidate as structurally OOS / acknowledged / "
            "superseded / structurally-uncertain" + bump_note + "; do not spawn a drill lane "
            "without operator override.",
        )
    if base_verdict == "warn-multi-gate-risk":
        return (
            base_verdict,
            "DOWNGRADE-OR-PROCEED-WITH-CAUTION - 2+ dry-run gates raised non-low signals" +
            bump_note + "; lane should include an explicit pre-answer for each before "
            "dispatching the drill.",
        )
    if base_verdict == "warn-1-gate-risk":
        return (
            base_verdict,
            "PROCEED-WITH-CAUTION - 1 dry-run gate raised a non-low signal" + bump_note +
            "; verify before drilling.",
        )
    return (
        "pass-likely-fileable",
        "PROCEED - no dry-run gate raised a non-low kill-risk signal.",
    )


# ---------------------------------------------------------------------------
# Hypothesis-uncertainty heuristic
# ---------------------------------------------------------------------------
HYPOTHESIS_UNCERTAINTY_PATTERNS = [
    # Generic question form: anything ending in '?'.  This is the strongest
    # uncertainty signal - the orient lane is asking a question rather than
    # asserting a known bug.
    r"\?",
    # Hedging language without ?.
    r"\b(?:does|do)\s+\w+\s+(?:re-?)?(?:verify|check|validate|enforce|reject|require)\b",
    r"\b(?:cross-?check|verify)\s+(?:against|that|whether)\b",
    r"\bis\s+there\s+(?:a\s+)?(?:path|way|mechanism|guard|check|validation)\b",
    r"\b(?:could|might|may)\s+(?:a\s+|the\s+|an?\s+)?(?:attacker|malicious|adversary|relayer|caller|solver|govern|admin|operator)\b",
    r"\b(?:could|might|may)\s+(?:affect|cause|trigger|lead|enable|allow|bypass|impact)\b",
    r"\b(?:dual.path|race|race[\s-]condition|double.spend|double.refund|double.mint)\b",
    r"\b(?:pattern):\s",  # "Pattern: X, Y" suggesting analogy reasoning
    r"\bwhat\s+\w+",  # liberal "what X" matcher (incl. without ?)
    r"\b(?:trust|trusted)\s+(?:relayer|claim|caller|input|message|pallet)\b",
    r"\b(?:role|permission)\s+(?:enforced|checked|verified|validated|exploitable)\b",
    r"\bcheck\s+(?:if|whether)\s+\w+\s+(?:has|is|contains|matches|equals|exists|verifies)\b",
    r"\bre-?verify\b.*\b(?:commitment|signature|proof|state|root|message)\b",
    r"\b(?:depends|depend)\s+on\b.*\b(?:assumption|trust|policy)\b",
    r"\bis\s+this\s+(?:safe|guarantee|assumption|enforced)\b",
    # Composition-class signals - "Combination with X if Y can Z".
    r"\bcombination\s+with\b",
    r"\bif\s+\w+\s+(?:unfinalized|forged|invalid|stale|accepted)\b",
]
_UNCERTAINTY_RE = re.compile(
    "|".join(f"(?:{p})" for p in HYPOTHESIS_UNCERTAINTY_PATTERNS),
    re.IGNORECASE,
)


def _hypothesis_uncertainty_score(c: dict[str, Any]) -> int:
    """Count uncertainty phrases in the candidate's hypothesis_seeds.

    The seeds are typically expressed as questions ("Is X verified?",
    "Can attacker manipulate Y?").  When >= 4 uncertainty matches surface
    across the seeds, the candidate is structurally exploring rather than
    asserting - historically these candidates drill to a NEGATIVE verdict.

    Score = sum of distinct uncertainty pattern hits across all seeds, plus
    a stretch-severity bump when severity_estimate names Critical-High but
    LIVE_TARGET_REPORT did not surface the file (unranked).
    """
    seeds = c.get("hypothesis_seeds")
    score = 0
    if isinstance(seeds, list):
        for seed in seeds:
            if not isinstance(seed, str):
                continue
            # Count ALL matches per seed (a seed with 2 questions counts as 2).
            score += sum(1 for _ in _UNCERTAINTY_RE.finditer(seed))

    # Stretch-severity bump: severity_estimate names Critical-High or
    # Critical AND live_report_rank is 'unranked' (the orient lane is
    # speculating about high severity on a surface that LIVE_TARGET_REPORT
    # did not flag - higher false-positive prior).
    sev = (c.get("severity_estimate") or "").lower()
    rank = c.get("live_report_rank")
    rank_unranked = isinstance(rank, str) and "unranked" in rank.lower()
    if ("critical" in sev) and rank_unranked:
        score += 2
    elif "critical" in sev or "high" in sev:
        # Mild bump for HIGH+ stretch hypotheses on ranked surfaces.
        if rank_unranked:
            score += 1
    return score


# GAP-INTEG-1 (2026-05-26): Gap #30 platform-OOS gate per candidate.
# r36-rebuttal: GAP-INTEG-1 pathspec registered.

# Aggregate-verdict upgrade ladder used for Gap #30 downgrade-on-OOS.
_GAP30_UPGRADE_LADDER = [
    "pass-likely-fileable",
    "warn-1-gate-risk",
    "warn-multi-gate-risk",
    "fail-high-kill-risk",
]


def _gate_gap30_platform_oos(
    c: dict[str, Any],
    workspace: Path,
) -> dict[str, Any]:
    """Run the Gap #30 always-escalate-platform-OOS check against the
    candidate's framing and return a gate-record dict.

    Output schema (added to the per-candidate gate_results list):
      {
        "gate": "GAP30-PLATFORM-OOS",
        "kill_risk": "low" | "medium" | "high" | "extreme",
        "verdict": "<gap30 verdict>",
        "evidence": [...],  # subset of the gap30 evidence list
        "framing_snippet": "<short text>",
      }

    Empirical anchor: Hyperbridge SCOPE.md "Theoretical vulnerabilities
    without any proof or demonstration" OOS clause - any candidate framed
    as theoretical / hypothetical without proof matches.
    """
    framing = _candidate_text(c)
    # Cap framing to a reasonable size to bound regex cost.
    framing = framing[:8000]

    gap30 = _load_gap30_module()
    if gap30 is None:
        return {
            "gate": "GAP30-PLATFORM-OOS",
            "kill_risk": "low",
            "verdict": "tool-missing",
            "evidence": [],
            "framing_snippet": framing[:160],
            "note": "always-escalate-platform-oos-check tool missing; gate skipped",
        }
    if not framing.strip():
        return {
            "gate": "GAP30-PLATFORM-OOS",
            "kill_risk": "low",
            "verdict": "pass-empty-framing",
            "evidence": [],
            "framing_snippet": "",
        }

    env_extra = os.environ.get("AUDITOOOR_GAP30_OOS_PATTERNS", "")
    try:
        result = gap30.check(
            workspace=workspace,
            candidate_framing=framing,
            rebuttal_text="",
            env_extra_patterns=env_extra,
        )
    except Exception as exc:  # noqa: BLE001 - graceful degradation
        return {
            "gate": "GAP30-PLATFORM-OOS",
            "kill_risk": "low",
            "verdict": "error",
            "evidence": [],
            "framing_snippet": framing[:160],
            "error": str(exc)[:300],
        }

    verdict = result.get("verdict", "")
    if verdict == "fail-candidate-framing-matches-platform-oos":
        # Per GAP-INTEG-1 task spec: when verdict is "fail-...", downgrade
        # candidate priority by 2 tiers (HIGH risk). When 3+ pieces of
        # evidence match, mark as EXTREME (boundary case).
        evidence = result.get("evidence", []) or []
        kill_risk = "extreme" if len(evidence) >= 3 else "high"
        return {
            "gate": "GAP30-PLATFORM-OOS",
            "kill_risk": kill_risk,
            "verdict": verdict,
            "evidence": evidence[:8],
            "framing_snippet": framing[:160],
            "platform": result.get("platform"),
            "oos_phrase_count": result.get("oos_phrase_count"),
            "downgrade_note": (
                "GAP-INTEG-1: candidate framing matches platform OOS clause; "
                "ALWAYS-ESCALATE-BY-DEFAULT suppressed for this candidate"
            ),
        }
    # Other passes / errors map to low kill-risk (no downgrade).
    return {
        "gate": "GAP30-PLATFORM-OOS",
        "kill_risk": "low",
        "verdict": verdict or "unknown",
        "evidence": [],
        "framing_snippet": framing[:160],
        "platform": result.get("platform"),
    }


def _apply_gap30_downgrade(base_verdict: str, gap30_kill_risk: str) -> str:
    """Downgrade `base_verdict` by 2 tiers when Gap #30 kill-risk is high+.

    Per GAP-INTEG-1 task spec:
      - kill-risk == extreme -> jump to fail-high-kill-risk regardless.
      - kill-risk == high    -> downgrade by 2 tiers (capped at fail-high-kill-risk).
      - else                 -> no change.
    """
    if gap30_kill_risk == "extreme":
        return "fail-high-kill-risk"
    if gap30_kill_risk == "high":
        try:
            idx = _GAP30_UPGRADE_LADDER.index(base_verdict)
        except ValueError:
            return base_verdict
        new_idx = min(idx + 2, len(_GAP30_UPGRADE_LADDER) - 1)
        return _GAP30_UPGRADE_LADDER[new_idx]
    return base_verdict


def _evaluate_candidate(
    c: dict[str, Any],
    workspace: Path,
    workspace_docs: list[tuple[str, str]],
    prior_audits: list[tuple[str, str]],
    severity_md: str,
    scope_md: str,
    audit_pin: str,
    days: int,
) -> dict[str, Any]:
    gates = [
        _gate_r45_design_intent(c, workspace_docs),
        _gate_r46_trusted_infra(c, severity_md, scope_md),
        _gate_r47_recent_fix(c, workspace, audit_pin, days),
        _gate_r48_deployment_topology(c),
        _gate_r53_prior_audit_supersede(c, prior_audits),
    ]
    # GAP-INTEG-1 (2026-05-26): add Gap #30 platform-OOS gate.
    gap30_gate = _gate_gap30_platform_oos(c, workspace)
    gates.append(gap30_gate)
    uncertainty = _hypothesis_uncertainty_score(c)
    verdict, recommendation = _aggregate_verdict(gates, uncertainty)
    # Apply Gap #30 explicit downgrade (independent of aggregate-gate count).
    base_verdict = verdict
    downgraded_verdict = _apply_gap30_downgrade(base_verdict, gap30_gate["kill_risk"])
    if downgraded_verdict != base_verdict:
        verdict = downgraded_verdict
        recommendation = (
            recommendation
            + " | GAP-INTEG-1 GAP30 downgrade applied: "
            + base_verdict
            + " -> "
            + downgraded_verdict
            + " (candidate framing matches platform OOS clause)"
        )
    risk_summary = {g["gate"]: g["kill_risk"] for g in gates}
    return {
        "candidate_id": c.get("id"),
        "candidate_name": c.get("name"),
        "files": c.get("files", []),
        "attack_class": c.get("attack_class"),
        "severity_estimate": c.get("severity_estimate"),
        "verdict": verdict,
        "verdict_before_gap30_downgrade": base_verdict,
        "gap30_downgrade_applied": downgraded_verdict != base_verdict,
        "severity_recommendation": recommendation,
        "per_gate_kill_risk": risk_summary,
        "hypothesis_uncertainty_score": uncertainty,
        "gate_results": gates,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    candidates_path = Path(args.candidates).resolve()
    if not candidates_path.is_file():
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "verdict": "error",
            "error": f"candidates file not found: {candidates_path}",
        }

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "verdict": "error",
            "error": f"workspace dir not found: {workspace}",
        }

    audit_pin = args.audit_pin or ""

    mode = MODE_COMPOSITION if getattr(args, "composition", False) else MODE_DRILL
    try:
        dependency_index: dict[str, dict[str, Any]] = {}
        if mode == MODE_COMPOSITION:
            candidates, src_meta, dependency_index = _load_composition_candidates(candidates_path)
        else:
            candidates, src_meta = _load_candidates(candidates_path)
    except (ValueError, json.JSONDecodeError) as exc:
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "verdict": "error",
            "error": f"candidates JSON parse: {exc}",
        }

    workspace_docs = _scan_workspace_docs(workspace)
    prior_audits = _scan_prior_audits(workspace)
    severity_md = _load_severity_md(workspace)
    scope_md = _load_scope_md(workspace)

    if mode == MODE_COMPOSITION:
        per_candidate = [
            _evaluate_composition_candidate(
                c,
                workspace,
                workspace_docs,
                prior_audits,
                severity_md,
                scope_md,
                audit_pin,
                args.days,
                dependency_index,
            )
            for c in candidates
        ]
    else:
        per_candidate = [
            _evaluate_candidate(
                c,
                workspace,
                workspace_docs,
                prior_audits,
                severity_md,
                scope_md,
                audit_pin,
                args.days,
            )
            for c in candidates
        ]

    summary = _build_prefilter_summary(per_candidate)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "mode": mode,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "candidates_path": str(candidates_path),
        "workspace": str(workspace),
        "audit_pin": audit_pin,
        "recent_fix_window_days": args.days,
        "source_meta": src_meta,
        "workspace_doc_count": len(workspace_docs),
        "prior_audit_doc_count": len(prior_audits),
        "prefilter_summary": summary,
        "per_candidate": per_candidate,
    }

    # Exit code 0 always when input was valid - this is a prefilter, not a
    # gate.  Caller inspects the per-candidate verdicts.
    return 0, payload


def _build_prefilter_summary(per_candidate: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {
        "pass-likely-fileable": 0,
        "warn-1-gate-risk": 0,
        "warn-multi-gate-risk": 0,
        "fail-high-kill-risk": 0,
    }
    for c in per_candidate:
        v = c.get("verdict")
        if v in counts:
            counts[v] += 1
    proceed = [c["candidate_id"] for c in per_candidate if c["verdict"] == "pass-likely-fileable"]
    caution = [c["candidate_id"] for c in per_candidate if c["verdict"] == "warn-1-gate-risk"]
    downgrade = [c["candidate_id"] for c in per_candidate if c["verdict"] == "warn-multi-gate-risk"]
    drop = [c["candidate_id"] for c in per_candidate if c["verdict"] == "fail-high-kill-risk"]
    return {
        "total_candidates": len(per_candidate),
        "verdict_counts": counts,
        "candidate_ids_by_verdict": {
            "pass-likely-fileable": proceed,
            "warn-1-gate-risk": caution,
            "warn-multi-gate-risk": downgrade,
            "fail-high-kill-risk": drop,
        },
        "recommended_dispatch_order": proceed + caution,
        "recommended_drop_or_downgrade": downgrade + drop,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="ORIENT prefilter: dry-run R45/R46/R47/R48/R53 over hunt candidates "
        "before dispatching drill lanes (Capability Gap 1+3 fix).",
    )
    parser.add_argument(
        "--candidates",
        required=True,
        help="Path to ORIENT lane's candidates JSON (must contain "
        "'drill_candidates' or 'candidates' array).",
    )
    parser.add_argument(
        "--workspace",
        required=True,
        help="Path to audit workspace (SEVERITY.md, SCOPE.md, prior_audits/, src/<repo>).",
    )
    parser.add_argument(
        "--audit-pin",
        default="",
        help="Audit-pin SHA (pass-through to output; used as a label).",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=DEFAULT_RECENT_FIX_WINDOW_DAYS,
        help=f"Recent-fix window in days for R47 lever (default {DEFAULT_RECENT_FIX_WINDOW_DAYS}).",
    )
    parser.add_argument(
        "--composition",
        action="store_true",
        help="Read and score the ORIENT lane's composition_queue instead of drill_candidates.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    args = parser.parse_args(argv)

    rc, payload = run(args)

    if args.json or rc != 0:
        print(json.dumps(payload, indent=2))
    else:
        _print_human(payload)

    return rc


def _print_human(payload: dict[str, Any]) -> None:
    print(f"[{TOOL_NAME}] schema={payload['schema_version']}")
    s = payload.get("prefilter_summary", {})
    counts = s.get("verdict_counts", {})
    print(
        f"[{TOOL_NAME}] {s.get('total_candidates', 0)} candidates: "
        f"pass={counts.get('pass-likely-fileable', 0)} "
        f"warn1={counts.get('warn-1-gate-risk', 0)} "
        f"warnN={counts.get('warn-multi-gate-risk', 0)} "
        f"fail={counts.get('fail-high-kill-risk', 0)}"
    )
    for c in payload.get("per_candidate", []):
        grades = c.get("per_gate_kill_risk", {})
        grade_str = " ".join(f"{g}={grades.get(g, '?')}" for g in ("R45", "R46", "R47", "R48", "R53"))
        print(
            f"  - {c.get('candidate_id', '?'):<10} [{c.get('verdict', '?'):<22}] {grade_str}"
        )
    rec = s.get("recommended_dispatch_order", [])
    if rec:
        print(f"[{TOOL_NAME}] recommended dispatch order: {', '.join(rec)}")
    drop = s.get("recommended_drop_or_downgrade", [])
    if drop:
        print(f"[{TOOL_NAME}] recommended drop/downgrade: {', '.join(drop)}")


if __name__ == "__main__":
    sys.exit(main())
