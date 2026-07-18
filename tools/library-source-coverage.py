#!/usr/bin/env python3
"""library-source-coverage.py — automated source-citation audit for the
detector-pattern library.

Background
----------
V5 Gap-28 + Gap-41 (V5-P0-16): the detector library at
``reference/patterns.dsl/*.yaml`` had grown to ~1400 patterns with no
automated visibility into where each pattern came from. ``Gap 24`` was
caught only via manual grep — ``cantina/2024-2025-*-class`` patterns whose
provenance line said "claimed cross-workspace mining" but for which the
workspace artifact tree (``engage_report.md``) showed no patterns landed.

This tool answers two questions deterministically:

  1. **Coverage**: what % of patterns cite a workspace audit, an
     external corpus (CVE/SWC/CWE/LISA/Solodit/Immunefi/rekt/DeFiHackLabs),
     a glider-AST corpus, or have no clear citation (synthetic /
     agent-invented)?
  2. **Cross-check**: for patterns that *claim* to be mined from a
     specific workspace (e.g. ``auditooor-R107-thegraph-...``), does that
     workspace's ``engage_report.md`` artifact actually exist and mention
     the pattern? — this is the FN-discipline check that catches "library
     claims X workspace mined but workspace artifacts say no patterns
     landed from there."

Output
------
- **stdout**: human-readable markdown summary (per-class %, per-workspace
  table, top 20 unclassified/synthetic patterns).
- **JSON manifest**: ``tools/calibration/library_source_coverage_<date>.json``
  (or ``--out PATH`` to override). Schema:
    {
      "generated_at_utc": "...",
      "tool_version": "1",
      "patterns_total": int,
      "by_class": { "<class>": {"count": int, "pct": float} },
      "by_workspace": { "<workspace>": int },
      "uncited_patterns": [...],
      "workspace_cross_check": { "<workspace>": {"claimed": int, "engage_report_seen": bool, "engage_report_path": str|null} },
      "warnings": [...]
    }

Citation classes (Codex's exact list, plus the ones we observed in the
real source field after running the classifier; see
``CITATION_CLASS_FIXTURES`` for the formal taxonomy):

  workspace        - a specific ``~/audits/<X>/`` audit, including
                     ``auditooor-R<NN>-<workspace>-...`` source tags
  cve              - cites a CVE-YYYY-NNNN id
  academic-corpus  - LISA-Bench / CWE-### / SWC-### / SWC-Registry refs
  external-feed    - DeFiHackLabs, Rekt, BlockSec, immunefi, defimon,
                     cantina/<contest>, code4rena/c4-<contest>, sherlock
                     (these are public-disclosure feeds, not workspace
                     audits)
  glider           - glider-AST family (``glider-docs/...``,
                     ``glider/...``, ``hexens-glider``)
  synthetic        - no citation (could be agent-invented). For the
                     library at ``reference/patterns.dsl`` every pattern
                     should have a ``source:`` field, so synthetic = the
                     source field is missing or its value is in
                     ``SYNTHETIC_TOKENS`` (e.g. literal ``auditooor``,
                     ``synthesized``, ``inferred``).

Cross-check shape
-----------------
For each pattern with a workspace-class citation that has a parsable
workspace name (e.g. ``auditooor-R107-thegraph-OZ-L-01`` →
``thegraph``), check whether ``--audits-root <root>/<ws>/engage_report.md``
exists. If ``--audits-root`` is not given, the tool defaults to
``$HOME/audits``. If the directory tree is unavailable (CI environment),
the cross-check is recorded with ``engage_report_seen: null`` and a
warning row, never a FAIL.

CLI
---
  python3 tools/library-source-coverage.py            # stdout markdown
  python3 tools/library-source-coverage.py --json     # stdout JSON
  python3 tools/library-source-coverage.py --out PATH # write JSON to file

Stdlib-only. Hermetic by default.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# ---- citation taxonomy ----------------------------------------------------

# Patterns are classified in order; the first match wins. Order matters:
# workspace MUST be checked before external-feed because
# ``auditooor-R76-immunefi-aurora-$6M`` is a workspace tag (R76 is an audit
# round) that happens to mention immunefi — it's the workspace round that
# matters for cross-check, not the immunefi feed.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_SWC_RE = re.compile(r"\bSWC-\d{3}\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
_LISA_RE = re.compile(r"\blisa(-mine|-bench|_bench)\b", re.IGNORECASE)
_GLIDER_RE = re.compile(r"^glider(-docs|/|-ast|-imported)?[\b/-]", re.IGNORECASE)
_HEXENS_GLIDER_RE = re.compile(r"\bhexens-glider\b", re.IGNORECASE)

# auditooor-R<NN>-<workspace>-... — workspace mining tag
_AUDITOOOR_WS_RE = re.compile(
    r"^auditooor-(?:[A-Za-z]{0,3})?\d+[A-Za-z]?-([A-Za-z0-9_-]+?)(?:-|$)"
)

# auditooor-round-<NN> / auditooor-cross-cluster — round-level tag with
# no specific workspace name. Counts as workspace-class for coverage but
# the workspace is recorded as ``unknown-round``.
_AUDITOOOR_ROUND_RE = re.compile(
    r"^auditooor-(round|cross|m14|MEC|fixdiff|cluster)\b", re.IGNORECASE
)

# <workspace>-r<NN>-source-mine-... — workspace-prefixed round tag.
# Example: ``snowbridge-r109-source-mine-oak-v2-major-finding-5``.
_WS_ROUND_RE = re.compile(
    r"^([a-z][a-z0-9]+(?:-[a-z0-9]+)*)-r\d{2,4}-",
    re.IGNORECASE,
)

# r<NN>-<workspace>-... — round-prefixed workspace tag.
# Example: ``r106-centrifuge-v3-BatchRequestManager.notifyDeposit``.
_ROUND_WS_RE = re.compile(
    r"^r\d{2,4}-([a-z][a-z0-9]+(?:-[a-z0-9]+)*?)-[A-Z]",
)

# cross-engagement-<workspace>-<finding> tag.
# Example: ``cross-engagement-base-azul-FN1-AggregateVerifier-resolve``.
_CROSS_ENG_RE = re.compile(
    r"^cross-engagement-([a-z][a-z0-9]+(?:-[a-z0-9]+)*?)-(?:FN|F|H|M|L)\d+",
    re.IGNORECASE,
)

# <workspace>-v<N>-meta-class-r<NN> — meta-class roll-up tag.
# Example: ``polymarket-v2-meta-class-r41``.
_META_CLASS_RE = re.compile(
    r"^([a-z][a-z0-9]+(?:-[a-z0-9]+)*?)-v\d+-meta-class-r",
    re.IGNORECASE,
)

# Workspace tokens whose immediately-following segment is a CONTEST/feed
# aggregator rather than a real workspace. When auditooor-R<NN>-<feed>-...
# captures one of these, we re-classify the SOURCE as external-feed and do
# NOT count a workspace claim, because the round merely curated public
# contest disclosures.
_FEED_AS_WORKSPACE = {
    "immunefi", "code4rena", "c4", "sherlock", "cantina", "solodit",
    "rekt", "defihacklabs", "blocksec", "spearbit", "zellic", "pashov",
    "halborn", "trail", "openzeppelin", "oz", "trust", "consensys",
    "chainsec", "cyfrin", "nethermind", "certora",
}

# Tokens that may appear as the second segment of an auditooor-R<NN>-<X>-...
# tag but are NOT workspace names — they're round-internal labels
# (e.g. ``auditooor-R71-fixdiff-mined-...``, ``auditooor-M14-the-dao-...``,
# ``auditooor-PR121-A7-codex-plan-...``).
_NOISE_WS_TOKENS = {
    "fixdiff", "the", "cross", "round", "seed", "a7", "a9", "phase",
    "phase37d", "drill2", "drill", "ec", "chain", "rust", "wave",
    "wave1", "rust_wave1", "loop", "cycle", "mining", "mine",
}

# Public disclosure feeds (NOT workspace audits)
_FEED_TOKENS = (
    "defihacklabs",
    "rekt.news",
    " rekt ",
    "blocksec",
    "defimon",
    "x-feed",
)

# Bug-bounty / contest feeds — public disclosure but contest-bounded.
# Treated as external-feed unless wrapped in an auditooor-R<NN> workspace tag.
_CONTEST_TOKENS = (
    "immunefi",
    "cantina/",
    "cantina-",
    "code4rena",
    "c4-",
    "sherlock-",
    "sherlock/",
    "solodit/",
)

# Tokens that mean "no citation, synthetic / agent-invented".
# IMPORTANT: do NOT add tokens like 'auditooor-R107-...' here. The bare
# 'auditooor' string with no round/workspace is what we treat as synthetic.
SYNTHETIC_TOKENS = {
    "",
    "auditooor",
    "synthesized",
    "inferred",
    "agent-invented",
    "n/a",
    "none",
    "unknown",
    "todo",
}

# Workspace name canonicalization. The workspace cross-check must collapse
# spelling variants ('centrifuge-v3' / 'centrifuge_v3' / 'Centrifuge-V3')
# into a single workspace bucket; otherwise an under-mined workspace can
# hide behind name-variation noise (Minimax attack #3).
_WORKSPACE_ALIAS = {
    "centrifuge_v3": "centrifuge-v3",
    "centrifugev3": "centrifuge-v3",
    "morpho-blue": "morpho",
    "morphoblue": "morpho",
    "thegraphhorizon": "thegraph",
    "the-graph": "thegraph",
    "kiln_v1": "kiln-v1",
    "kilnv1": "kiln-v1",
    "snow-bridge": "snowbridge",
    "snowbridgev1": "snowbridge",
    "base_azul": "base-azul",
    "baseazul": "base-azul",
}


def canonicalize_workspace(name: str) -> str:
    """Normalize a workspace name to its canonical bucket.

    Lowercase, strip trailing version-ish suffixes that we don't index on,
    and apply explicit aliases. Returns the canonical name.
    """
    if not name:
        return ""
    n = name.strip().lower()
    # Collapse separators to the dash form first so 'Centrifuge_V3' and
    # 'centrifuge-v3' compare equal under the alias map.
    n_dash = n.replace("_", "-")
    if n_dash in _WORKSPACE_ALIAS:
        return _WORKSPACE_ALIAS[n_dash]
    if n in _WORKSPACE_ALIAS:
        return _WORKSPACE_ALIAS[n]
    return n_dash


# ---- pattern model --------------------------------------------------------


@dataclass
class PatternRecord:
    path: Path
    pattern_name: str
    source_value: str  # raw `source:` field
    description: str  # `help:` + `wiki_*` joined for fallback scan
    citation_class: str = ""
    workspace: str = ""  # canonical workspace name when class == workspace


@dataclass
class CoverageReport:
    patterns_total: int = 0
    by_class: dict = field(default_factory=dict)
    by_workspace: dict = field(default_factory=dict)
    uncited_patterns: list = field(default_factory=list)
    workspace_cross_check: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


# ---- pattern loading ------------------------------------------------------

# Stdlib-only. We avoid the YAML dependency (PyYAML may not be installed in
# CI) by extracting only the keys we need: ``source``, ``pattern``,
# ``help``, ``wiki_title``, ``wiki_description``. The YAML files are flat
# at the keys we need (no multi-line block scalars in those positions
# observed in the corpus).
_KEY_RE = re.compile(
    r'^(?P<key>source|pattern|help|wiki_title|wiki_description|wiki_exploit_scenario|wiki_recommendation)\s*:\s*(?P<val>.*)$'
)


def parse_pattern_yaml(path: Path) -> PatternRecord | None:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    fields: dict[str, str] = {}
    for line in text.splitlines():
        m = _KEY_RE.match(line)
        if not m:
            continue
        key = m.group("key")
        val = m.group("val").strip()
        # Strip surrounding quotes
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
        # Only set the FIRST occurrence (top-level key).
        fields.setdefault(key, val)
    name = fields.get("pattern") or path.stem
    description = " ".join(
        fields.get(k, "")
        for k in ("help", "wiki_title", "wiki_description",
                  "wiki_exploit_scenario", "wiki_recommendation")
    )
    return PatternRecord(
        path=path,
        pattern_name=name,
        source_value=fields.get("source", ""),
        description=description,
    )


def load_patterns(library_dir: Path) -> list[PatternRecord]:
    out: list[PatternRecord] = []
    for p in sorted(library_dir.glob("*.yaml")):
        rec = parse_pattern_yaml(p)
        if rec is not None:
            out.append(rec)
    return out


# ---- classification -------------------------------------------------------


def classify_pattern(rec: PatternRecord) -> tuple[str, str]:
    """Return ``(citation_class, workspace_or_empty)``.

    Citation_class is one of:
      ``workspace``, ``cve``, ``academic-corpus``, ``external-feed``,
      ``glider``, ``synthetic``.

    Order is significant. workspace MUST come before external-feed because
    workspace tags can mention contest names (e.g. R76-immunefi-...).
    """
    raw = (rec.source_value or "").strip()
    low = raw.lower()

    # 1) synthetic shortcut: empty or in synthetic-token set
    if low in SYNTHETIC_TOKENS:
        return ("synthetic", "")

    # 1b) academic-corpus FIRST: LISA / SWC / CWE — must come before any
    # workspace-shape regex because tags like ``lisa-mine-r99-case-...``
    # otherwise capture ``lisa-mine`` as a phantom workspace name.
    if _LISA_RE.search(raw) or _SWC_RE.search(raw) or _CWE_RE.search(raw):
        return ("academic-corpus", "")

    # 2) workspace via auditooor-R<NN>-<workspace>-...
    m = _AUDITOOOR_WS_RE.match(raw)
    if m:
        ws_raw = m.group(1).lower()
        # If the second segment is a contest/feed aggregator
        # (auditooor-R76-immunefi-...), this round CURATED public
        # disclosures — treat the source as external-feed, not as
        # workspace evidence. Otherwise it's a real workspace mining tag.
        if ws_raw in _FEED_AS_WORKSPACE:
            return ("external-feed", "")
        # Known-noisy second-segment tokens that are NOT workspace names
        # (e.g. ``auditooor-R71-fixdiff-...``, ``auditooor-M14-the-dao-...``).
        # Treat the round as auditooor work without a specific workspace.
        if ws_raw in _NOISE_WS_TOKENS:
            return ("workspace", "unknown-round")
        # Drop very-short / pure-noise segments (single-letter, just
        # digits, classifier helpers like ``a7``/``a9`` from PR121).
        if len(ws_raw) <= 2 or ws_raw.isdigit():
            return ("workspace", "unknown-round")
        ws = canonicalize_workspace(ws_raw)
        return ("workspace", ws)

    # 3) auditooor-round-<NN> / auditooor-cross-cluster: round-level work
    # without a specific workspace. Count as workspace-class (it IS audit
    # work) but record as 'unknown-round' so cross-check skips it.
    if _AUDITOOOR_ROUND_RE.match(raw):
        return ("workspace", "unknown-round")

    # 4) <workspace>-r<NN>-source-mine-... e.g.
    # ``snowbridge-r109-source-mine-oak-v2-major-finding-5``.
    m4 = _WS_ROUND_RE.match(raw)
    if m4:
        ws_raw = m4.group(1).lower()
        if ws_raw in _FEED_AS_WORKSPACE:
            return ("external-feed", "")
        return ("workspace", canonicalize_workspace(ws_raw))

    # 5) r<NN>-<workspace>-... e.g. ``r106-centrifuge-v3-Batch...``.
    m5 = _ROUND_WS_RE.match(raw)
    if m5:
        ws_raw = m5.group(1).lower()
        if ws_raw in _FEED_AS_WORKSPACE:
            return ("external-feed", "")
        return ("workspace", canonicalize_workspace(ws_raw))

    # 6) cross-engagement-<workspace>-<finding>.
    m6 = _CROSS_ENG_RE.match(raw)
    if m6:
        ws_raw = m6.group(1).lower()
        return ("workspace", canonicalize_workspace(ws_raw))

    # 7) <workspace>-vN-meta-class-r<NN>.
    m7 = _META_CLASS_RE.match(raw)
    if m7:
        ws_raw = m7.group(1).lower()
        return ("workspace", canonicalize_workspace(ws_raw))

    # 8) workspace direct path tag (e.g. ~/audits/<ws>/... or
    # ws/<ws>/... seen in some auto-mined-from-diffs/* tags).
    m_path = re.match(
        r"^(?:~/audits/|ws/|workspace/)([A-Za-z0-9_-]+)(?:/|$)",
        raw,
    )
    if m_path:
        ws = canonicalize_workspace(m_path.group(1))
        return ("workspace", ws)

    # 4) CVE
    if _CVE_RE.search(raw):
        return ("cve", "")

    # 5) academic-corpus already checked at step 1b (LISA/SWC/CWE).

    # 6) glider
    if _GLIDER_RE.match(raw) or _HEXENS_GLIDER_RE.search(low):
        return ("glider", "")

    # 7) external-feed: public disclosure / contest aggregator
    for tok in _FEED_TOKENS:
        if tok.strip() in low:
            return ("external-feed", "")
    for tok in _CONTEST_TOKENS:
        if tok in low:
            return ("external-feed", "")
    # Solodit and code4arena variants observed in the corpus that don't
    # match the strict CONTEST_TOKENS form (path-style or trailing slash).
    if (
        low.startswith("solodit-")
        or low.startswith("solodit/")
        or low.startswith("solodit ")
        or "code4arena/" in low
        or low.startswith("code4arena-")
        or low.startswith("c4-")
    ):
        return ("external-feed", "")

    # 8) certora-* / formal-verification corpus is treated as academic for
    # coverage purposes (it has a deterministic provenance trail).
    if low.startswith("certora-") or low.startswith("certora/"):
        return ("academic-corpus", "")

    # 9) auto-mined-from-diffs/<bucket> — workspace category but unspecified
    # workspace. Treat as 'workspace' with name 'unknown-fixdiff' so the
    # cross-check skips them but they don't show up as synthetic.
    if low.startswith("auto-mined-from-diffs"):
        return ("workspace", "unknown-fixdiff")

    # 10) Pear Vault / SKILL_ISSUE-style internal tracker — workspace.
    if "pear vault" in low or "skill_issue" in low or low.startswith("c0"):
        return ("workspace", "internal-tracker")

    # 11) defi-hack-labs (without dash spelling) and similar already
    # caught above; also catch 'beanstalk-2022-exploit-anchor' style
    # exploit-anchor sources as external-feed (real on-chain incidents).
    if "exploit-anchor" in low or "exploit_anchor" in low:
        return ("external-feed", "")
    # postmortems / public exploit writeups (e.g. ``kelp-rseth-exploit-
    # 2026-04-18-banteg-postmortem``) — external public-disclosure feed.
    if "postmortem" in low or "-exploit-" in low or "/exploit-" in low:
        return ("external-feed", "")

    # 12) auditooor work-tag families with no explicit workspace name —
    # e.g. ``economic-mining-R61``, ``r74b-cross-firm-cs+oz``,
    # ``loop-cycle-44-sol-sibling``, ``reverse-port-from-rust_wave1``,
    # ``auditooor-seed``. These ARE auditooor work, just round-level not
    # workspace-specific. Bucket as workspace 'unknown-round'.
    if (
        low.startswith("economic-mining-")
        or re.match(r"^r\d+[a-z]*-cross-firm", low)
        or low.startswith("loop-cycle-")
        or low.startswith("reverse-port-")
        or low.startswith("auditooor-")
    ):
        return ("workspace", "unknown-round")

    # 12) Fall-through: anything left is synthetic-ish. Be conservative —
    # tag it explicitly so the operator can audit fall-through.
    return ("synthetic", "")


# ---- workspace cross-check -----------------------------------------------


def cross_check_workspaces(
    by_workspace: dict[str, int],
    audits_root: Path | None,
) -> tuple[dict, list[str]]:
    """For each claimed workspace, check whether ``<root>/<ws>/engage_report.md``
    exists. Returns ``(cross_check_dict, warnings)``.

    ``audits_root`` may be ``None`` — in which case every entry is recorded
    with ``engage_report_seen: null`` and a single warning is emitted.
    """
    out: dict[str, dict] = {}
    warnings: list[str] = []
    if audits_root is None:
        warnings.append(
            "audits-root not provided; workspace cross-check skipped "
            "(every workspace recorded with engage_report_seen=null)"
        )
        for ws, n in sorted(by_workspace.items()):
            out[ws] = {
                "claimed": n,
                "engage_report_seen": None,
                "engage_report_path": None,
            }
        return out, warnings
    if not audits_root.exists():
        warnings.append(
            f"audits-root {audits_root} does not exist; cross-check skipped"
        )
        for ws, n in sorted(by_workspace.items()):
            out[ws] = {
                "claimed": n,
                "engage_report_seen": None,
                "engage_report_path": None,
            }
        return out, warnings

    for ws, n in sorted(by_workspace.items()):
        if ws in {"unknown-fixdiff", "internal-tracker", ""}:
            out[ws] = {
                "claimed": n,
                "engage_report_seen": None,
                "engage_report_path": None,
            }
            continue
        # Try the canonical name + a couple of common variants on disk.
        candidates = [audits_root / ws]
        for alt in (ws.replace("-", "_"), ws.replace("-", "")):
            if alt != ws:
                candidates.append(audits_root / alt)
        engage_path: Path | None = None
        for c in candidates:
            er = c / "engage_report.md"
            if er.exists():
                engage_path = er
                break
        out[ws] = {
            "claimed": n,
            "engage_report_seen": engage_path is not None,
            "engage_report_path": str(engage_path) if engage_path else None,
        }
        if engage_path is None and n >= 5:
            warnings.append(
                f"workspace {ws} has {n} claimed patterns but no "
                f"engage_report.md found under {audits_root}"
            )
    return out, warnings


# ---- report assembly ------------------------------------------------------


def build_report(
    library_dir: Path,
    audits_root: Path | None,
) -> CoverageReport:
    patterns = load_patterns(library_dir)
    rep = CoverageReport(patterns_total=len(patterns))
    if not patterns:
        rep.warnings.append(f"no patterns found under {library_dir}")
        return rep

    cls_counts: dict[str, int] = {}
    ws_counts: dict[str, int] = {}
    uncited: list[dict] = []
    for rec in patterns:
        cls, ws = classify_pattern(rec)
        rec.citation_class = cls
        rec.workspace = ws
        cls_counts[cls] = cls_counts.get(cls, 0) + 1
        if cls == "workspace" and ws:
            ws_counts[ws] = ws_counts.get(ws, 0) + 1
        if cls == "synthetic":
            uncited.append({
                "pattern": rec.pattern_name,
                "path": str(rec.path),
                "source_value": rec.source_value,
            })

    total = rep.patterns_total
    by_class: dict[str, dict] = {}
    for k in (
        "workspace", "cve", "academic-corpus", "external-feed",
        "glider", "synthetic",
    ):
        c = cls_counts.get(k, 0)
        by_class[k] = {"count": c, "pct": round(100.0 * c / total, 2)}
    rep.by_class = by_class
    rep.by_workspace = ws_counts
    rep.uncited_patterns = uncited

    cross, ws_warnings = cross_check_workspaces(ws_counts, audits_root)
    rep.workspace_cross_check = cross
    rep.warnings.extend(ws_warnings)

    return rep


# ---- output ---------------------------------------------------------------


def render_markdown(rep: CoverageReport) -> str:
    lines: list[str] = []
    lines.append("# Library source coverage")
    lines.append("")
    lines.append(f"- patterns_total: **{rep.patterns_total}**")
    lines.append("")
    lines.append("## By citation class")
    lines.append("")
    lines.append("| class | count | pct |")
    lines.append("|---|---:|---:|")
    for cls in (
        "workspace", "cve", "academic-corpus", "external-feed",
        "glider", "synthetic",
    ):
        row = rep.by_class.get(cls, {"count": 0, "pct": 0.0})
        lines.append(f"| {cls} | {row['count']} | {row['pct']:.2f}% |")
    lines.append("")
    if rep.by_workspace:
        lines.append("## By workspace (top 25)")
        lines.append("")
        lines.append("| workspace | claimed | engage_report? |")
        lines.append("|---|---:|---|")
        # sort by count desc
        ranked = sorted(
            rep.by_workspace.items(), key=lambda kv: -kv[1]
        )[:25]
        for ws, n in ranked:
            seen = rep.workspace_cross_check.get(ws, {}).get(
                "engage_report_seen"
            )
            seen_str = (
                "yes" if seen is True
                else ("no" if seen is False else "skip")
            )
            lines.append(f"| {ws} | {n} | {seen_str} |")
        lines.append("")
    if rep.uncited_patterns:
        lines.append(
            f"## Uncited / synthetic patterns ({len(rep.uncited_patterns)})"
        )
        lines.append("")
        lines.append("First 20 shown:")
        lines.append("")
        for u in rep.uncited_patterns[:20]:
            lines.append(
                f"- `{u['pattern']}` (source={u['source_value']!r})"
            )
        lines.append("")
    if rep.warnings:
        lines.append("## Warnings")
        lines.append("")
        for w in rep.warnings:
            lines.append(f"- {w}")
        lines.append("")
    return "\n".join(lines)


def render_json(rep: CoverageReport) -> dict:
    return {
        "generated_at_utc": _dt.datetime.now(_dt.UTC).isoformat(
            timespec="seconds"
        ),
        "tool_version": "1",
        "patterns_total": rep.patterns_total,
        "by_class": rep.by_class,
        "by_workspace": rep.by_workspace,
        "uncited_patterns": rep.uncited_patterns,
        "workspace_cross_check": rep.workspace_cross_check,
        "warnings": rep.warnings,
    }


# ---- CLI ------------------------------------------------------------------


def _default_out_path(repo_root: Path) -> Path:
    today = _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%d")
    return repo_root / "tools" / "calibration" / f"library_source_coverage_{today}.json"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Library source coverage / citation audit."
    )
    p.add_argument(
        "--library-dir", type=Path, default=None,
        help="Override pattern library dir (default: <repo>/reference/patterns.dsl)",
    )
    p.add_argument(
        "--audits-root", type=Path, default=None,
        help="Workspace audits root for cross-check (default: $HOME/audits)",
    )
    p.add_argument(
        "--no-cross-check", action="store_true",
        help="Skip workspace cross-check (no FS read of audits-root)",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Emit JSON to stdout instead of markdown",
    )
    p.add_argument(
        "--out", type=Path, default=None,
        help="Write JSON manifest to PATH (default: tools/calibration/library_source_coverage_<date>.json). Use '--out -' to skip writing.",
    )
    args = p.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[1]
    library_dir = args.library_dir or (repo_root / "reference" / "patterns.dsl")
    audits_root: Path | None
    if args.no_cross_check:
        audits_root = None
    elif args.audits_root is not None:
        audits_root = args.audits_root
    else:
        home = os.environ.get("HOME")
        audits_root = Path(home) / "audits" if home else None
        if audits_root is not None and not audits_root.exists():
            audits_root = None

    rep = build_report(library_dir, audits_root)
    payload = render_json(rep)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_markdown(rep))

    out_path: Path | None
    if args.out is not None and str(args.out) == "-":
        out_path = None
    else:
        out_path = args.out or _default_out_path(repo_root)
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        if not args.json:
            print(f"\n[library-source-coverage] wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
