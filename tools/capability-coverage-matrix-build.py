#!/usr/bin/env python3
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
"""capability-coverage-matrix-build.py - step 7: refresh the coverage matrix.

Builds / refreshes ``<WS>/HUNT_CAPABILITY_COVERAGE_MATRIX.md`` - a markdown
table with one row per in-scope cluster (from SCOPE.md), whose status cell
is COVERED when the cluster has >=1 hunt sidecar / skip-set / coverage
evidence and DARK otherwise. The matrix shape matches what
hunt-completeness-check.py signal (c) scans for (a
``*CAPABILITY_COVERAGE_MATRIX.md`` file; DARK rows fail the gate).

Deterministic, stdlib-only, offline-safe. The status assignment reuses the
same coverage-token logic the completeness gate uses (sidecar stems +
skip-set slugs), so the matrix and the gate agree.

CLI
---
    python3 tools/capability-coverage-matrix-build.py <workspace> [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.l36_capability_coverage_matrix.v1"
GATE = "L36-CAPABILITY-COVERAGE-MATRIX"
MATRIX_NAME = "HUNT_CAPABILITY_COVERAGE_MATRIX.md"
_DARK_TOKENS = ("dark", "uncovered", "not-covered", "not covered", "no-coverage", "no coverage", "gap")

_IN_SCOPE_SECTION_RE = re.compile(
    r"^(?:scope|in[- ]scope\b.*|assets? classes?|assets? in[- ]scope\b.*|"
    r"smart contracts? in[- ]scope\b.*|github targets?)$",
    re.IGNORECASE,
)
_OOS_SECTION_RE = re.compile(
    r"\b(?:out[- ]of[- ]scope|oos|assumptions?|target|protocol summary)\b",
    re.IGNORECASE,
)
_TITLE_SCOPE_RE = re.compile(r"\bscope\b", re.IGNORECASE)


# A "vulnerability classes" / "impacts" / "attack classes" section lists the
# IMPACT axis (mapped to the SEVERITY.md rubric, covered by the rubric-coverage
# gate), NOT in-scope CODE clusters. Treating its bullets as code clusters makes
# them permanently DARK in a code-coverage matrix (a code-unit hunt does not emit
# a token per impact-phrase). Detect + skip these sections generically.
_IMPACT_SECTION_RE = re.compile(
    r"\b(?:vulnerabilit|impact|attack\s+class|attack\s+vector|severit|rubric|"
    r"threat\s+model|bug\s+class)", re.IGNORECASE)


def _is_impact_class_heading(heading: str) -> bool:
    return bool(_IMPACT_SECTION_RE.search(heading or ""))


def _is_cluster_section(heading: str) -> bool:
    norm = re.sub(r"\s+", " ", heading.strip().lower())
    if not norm or _OOS_SECTION_RE.search(norm):
        return False
    return bool(_IN_SCOPE_SECTION_RE.match(norm))


def _is_title_scope_heading(heading: str, level: int) -> bool:
    return level == 1 and bool(_TITLE_SCOPE_RE.search(heading))


def _clean_cluster_name(value: str) -> str:
    # Unwrap markdown bold/code SPANS ("**Key**" -> "Key", "`x`" -> "x") so a
    # "**Key**: value" metadata bullet normalizes to "Key: value" and is then
    # caught by the metadata filter (without this, the leading '*' made the
    # metadata regex miss it and the header bullet became a spurious DARK cluster
    # row). Span-targeted (paired markers only) so glob paths like `src/**/*.sol`
    # - which have an unpaired '**' - are preserved verbatim.
    v = value.strip()
    v = re.sub(r"\*\*(.+?)\*\*", r"\1", v)   # bold span
    v = re.sub(r"`(.+?)`", r"\1", v)          # inline-code span
    name = re.split(r"\s+[-:(]", v.strip())[0].strip()
    return name.strip()


def _matrix_row_signal(cells: list[str], status_idx: int | None) -> str:
    if status_idx is not None and 0 <= status_idx < len(cells):
        return cells[status_idx].lower()
    if len(cells) >= 2:
        return " ".join(c.lower() for c in cells[1:])
    return " ".join(c.lower() for c in cells)


def _exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


def _read_text(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def _external_matrix_tokens(ws: Path) -> set[str]:
    tokens: set[str] = set()
    try:
        matrices = [
            c for c in ws.iterdir()
            if c.is_file()
            and c.name.endswith("CAPABILITY_COVERAGE_MATRIX.md")
            and c.name != MATRIX_NAME
        ]
    except OSError:
        matrices = []
    for matrix in matrices:
        txt = _read_text(matrix) or ""
        status_idx: int | None = None
        for raw in txt.splitlines():
            line = raw.strip()
            if not line.startswith("|") or "|" not in line[1:]:
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells if c):
                continue
            low_cells = [c.lower() for c in cells]
            header_hit = [
                i for i, c in enumerate(low_cells)
                if c in ("verdict", "status", "coverage")
            ]
            if header_hit:
                status_idx = header_hit[0]
                continue
            if not cells or cells[0].strip().lower() in ("cluster", "scope", "component"):
                continue
            signal = _matrix_row_signal(cells, status_idx)
            if any(re.search(rf"(?<![a-z]){re.escape(tok)}(?![a-z])", signal) for tok in _DARK_TOKENS):
                continue
            tokens.add(cells[0].replace("`", "").strip().lower())
    return {t for t in tokens if t}



# SCOPE.md intro/metadata bullets ("- Asset class: ...", "- Platform: ...",
# "- Program URL: ...", "- Audit pin: ...", "- Source", "- Local checkout: ...")
# are NOT in-scope clusters. They share the bullet shape and (when listed under
# the title heading) were wrongly counted as clusters, inflating the cluster
# count and making cluster-coverage / dark-families un-passable on any workspace
# whose SCOPE.md carries a metadata header. Filter them out generically.
_SCOPE_METADATA_KEYS = frozenset({
    "asset class", "platform", "program", "program url", "source", "audit pin",
    "local checkout", "license", "bounty", "max bounty", "severity", "website",
    "docs", "documentation", "contact", "reward", "rewards", "repo", "repository",
    "chain", "network", "ecosystem", "language", "commit", "pin", "scope",
    "in-scope", "in scope", "out-of-scope", "out of scope", "program rules",
    "rules", "eligibility", "acceptance", "asset", "url", "homepage", "live since",
    "submission selector", "asset class:", "build assumptions",
    # additional header/metadata keys seen across program SCOPE.md files
    "category", "source repo", "authoritative machine scope", "raw captured scope",
    "deployed-vs-head", "live-bounty caveat", "caveat", "kyc", "poc", "max payout",
    "deployed", "tags", "type", "kind",
    # program-preamble metadata keys (universal across SCOPE.md files): the
    # re-pin policy line and the start/findings counters are never code clusters.
    "pin policy", "max reward", "start", "findings", "findings submitted",
    "findings submitted to date", "platform url", "bounty url",
})

# A metadata bullet's VALUE often gives it away even when the key is novel: a URL,
# a long commit hash, a money amount, or a pipe-delimited badge list ("$2.5M |
# PoC required | KYC required") are program-metadata, never an in-scope code/impact
# cluster. Detect by value-shape so we are not whack-a-mole on key names.
_META_VALUE_RE = re.compile(
    r"https?://|\b[0-9a-f]{20,}\b|[$€£]\s?[\d,]|\|\s*(?:poc|kyc)\b",
    re.IGNORECASE,
)

# Provenance bullets describe WHERE / WHICH revision the code came from
# ("Deployed/audited version: tag `mainnet-v2.0.0`", "Pinned commit: <sha>",
# "Cloned at ..."), never an in-scope code cluster. They evade the "Label: value"
# branch below because (a) _clean_cluster_name strips the value at the ':' before
# this check runs, leaving a bare label, and (b) labels like "deployed/audited
# version" contain a '/' so the branch bails. A bullet whose residual label is
# LED BY a provenance word, or is built around the word "version", is metadata.
_META_PROVENANCE_WORDS = frozenset({
    "deployed", "audited", "pinned", "commit", "checkout", "clone", "cloned",
    "provenance", "revision",
})


# Known smart-contract audit firms - a SCOPE.md bullet led by one of these names a
# PRIOR-AUDIT report (R47/R53 dedup input), never an in-scope code/asset cluster.
_PRIOR_AUDIT_FIRMS = frozenset({
    "sherlock", "halborn", "spearbit", "cantina", "zellic", "trail", "consensys",
    "certik", "quantstamp", "hexens", "openzeppelin", "code4rena", "c4", "pashov",
    "macro", "chainsecurity", "trustsec", "guardian", "cyfrin", "peckshield",
})


def _is_deployment_address_bullet(raw: str) -> bool:
    """A SCOPE.md bullet that annotates DEPLOYED contract ADDRESSES - e.g.
    ``In-scope tokens (deployed): AXL 0x4677..E5f3, axlUSDC on Avax/BSC/...`` - is a
    deployment-address annotation, NOT a huntable code cluster: the wrapped tokens'
    CODE lives in the in-scope repo cluster (InterchainToken.sol under
    interchain-token-service). The parenthetical ``(deployed)`` + a 0x address after
    the colon defeats the Label:value key-regex (parens are excluded from the key
    charclass) AND _clean_cluster_name strips the value before _is_scope_metadata_bullet
    sees it, so ``In-scope tokens`` slips through as a permanently-DARK phantom cluster
    (axelar-sc 2026-07-12). Catch it on the RAW bullet. NEVER-FALSE-DROP: requires BOTH
    a deployment/in-scope-token label AND >=1 real 0x hex address in the value, so a
    genuine code-module cluster (which carries no on-chain address) is never dropped."""
    r = (raw or "").strip()
    if ":" not in r:
        return False
    label, _, value = r.partition(":")
    low_label = label.strip().lower()
    if not ("deployed" in low_label
            or "in-scope token" in low_label
            or "in scope token" in low_label):
        return False
    return bool(re.search(r"0x[0-9a-fA-F]{4,}", value))


def _is_scope_metadata_bullet(name: str) -> bool:
    n = (name or "").strip()
    if not n:
        return True
    if re.match(r"^https?://", n, re.I):
        return True
    low = n.lower().rstrip(":")
    if low in _SCOPE_METADATA_KEYS:
        return True
    # "Label: value" - filter when Label is a known meta key OR the value has a
    # metadata shape (url / hash / money / badge-list). Allow hyphens in the key
    # ("DEPLOYED-vs-HEAD", "LIVE-bounty caveat").
    m = re.match(r"^([A-Za-z][A-Za-z /-]{1,48}?)\s*:\s*(.*)$", n)
    if m and "/" not in m.group(1):
        key = m.group(1).strip().lower()
        value = m.group(2).strip()
        if key in _SCOPE_METADATA_KEYS:
            return True
        if value and _META_VALUE_RE.search(value):
            return True
    # Provenance bullet: residual label led by a provenance word, or a short
    # phrase built around "version" (e.g. "deployed/audited version", "audited
    # version", "pinned commit"). No real code-module cluster is named this way.
    _toks = [t for t in re.split(r"[^a-z0-9]+", low) if t]
    if _toks and (
        _toks[0] in _META_PROVENANCE_WORDS
        or ("version" in _toks and len(_toks) <= 3)
    ):
        return True
    # PROSE / PLACEHOLDER rows: a wrapped continuation line of a multi-line SCOPE.md
    # bullet (e.g. "backward incomplete-fix), and verify deployed bytecode matches the
    # pin before filing.") is a SENTENCE, not a code/asset cluster - it carries prose
    # punctuation ("), " / a mid-sentence period) and many words. And a literal
    # "... placeholder" bullet is a stub, never an in-scope cluster. Both became
    # permanently-DARK phantom clusters (NUVA 2026-06-30). Exclude generically.
    if "placeholder" in low:
        return True
    # PRIOR-AUDIT references (a SCOPE.md "PRIOR AUDITS (R47/R53 ...)" block lists
    # e.g. "Sherlock ProvLabs Collaborative 2025-12-17", "Halborn vault ... a53e2b")
    # are R47/R53 DEDUP inputs, not in-scope code/asset clusters to hunt. A whole-doc
    # title-scope (e.g. "NUVA Immunefi Scope") makes every bullet a candidate cluster,
    # so these leaked as permanently-DARK phantom clusters. A bullet LED BY a known
    # audit-firm token is a prior-audit reference. NUVA 2026-06-30.
    _first_tok = (re.split(r"[^a-z0-9]+", low, 1)[0] if low else "")
    if _first_tok in _PRIOR_AUDIT_FIRMS:
        return True
    if re.search(r"\)\s*,|\.\s+\w", n) and len(n.split()) >= 6:
        return True
    if len(n.split()) > 12:  # no real cluster/asset name is a 12+-word phrase
        return True
    return False


def _parse_scope_clusters(ws: Path) -> list[str]:
    scope = ws / "SCOPE.md"
    txt = _read_text(scope)
    if not txt:
        return []
    clusters: list[str] = []
    saw_heading = False
    active_section = True
    # Depth at which the currently-active in-scope section opened. A heading
    # DEEPER than this (a subsection nested inside an in-scope section, e.g.
    # "### Morpho V2" under "## In-scope repos") INHERITS active status - it is
    # still in-scope - unless it is itself an explicit OOS / impact-class
    # heading. Without this, product-group subsections under an in-scope section
    # were wrongly deactivated and every real repo cluster bullet was dropped,
    # leaving only preamble metadata bullets (cluster-coverage gate false-red).
    active_depth: int | None = None
    table_header: list[str] | None = None
    for raw in txt.splitlines():
        line = raw.strip()
        heading = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if heading:
            saw_heading = True
            depth = len(heading.group(1))
            title = heading.group(2)
            is_self_scope = (
                _is_title_scope_heading(title, depth) or _is_cluster_section(title)
            ) and not _is_impact_class_heading(title)
            # A subsection nested inside an active in-scope section inherits its
            # scope, unless this heading is itself OOS / impact-class.
            inherits = (
                active_section
                and active_depth is not None
                and depth > active_depth
                and not _OOS_SECTION_RE.search(
                    re.sub(r"\s+", " ", title.strip().lower())
                )
                and not _is_impact_class_heading(title)
            )
            active_section = is_self_scope or inherits
            if active_section and not inherits:
                # New top-of-scope section: record its depth as the anchor.
                active_depth = depth
            elif not active_section:
                active_depth = None
            table_header = None
            continue
        if saw_heading and not active_section:
            continue
        m = re.match(r"^[-*+]\s+(.+)$", line)
        if m:
            name = _clean_cluster_name(m.group(1))
            if (name and len(name) <= 120
                    and not _is_scope_metadata_bullet(name)
                    and not _is_deployment_address_bullet(m.group(1))):
                clusters.append(name)
            continue
        # Bare source-file path line (no markdown bullet): some SCOPE.md files list
        # the in-scope files as plain relative paths, one per line, not bullets
        # (Strata 2026-07-07: `contracts/tranches/utils/UD60x18Ext.sol` per line ->
        # this parser returned [] -> hunt-complete false-red fail-missing-cluster-
        # coverage while Step-1 had already enumerated 388 units from the same file).
        # Each such path IS a code cluster. Match a spaceless relative path ending in
        # a known source extension so prose/metadata lines are never captured.
        bare = re.match(
            r"^([\w./\\-]+\.(?:sol|go|rs|vy|cairo|move|py|ts|js|cpp|hpp))$", line)
        if bare:
            name = _clean_cluster_name(bare.group(1))
            if name and len(name) <= 200 and not _is_scope_metadata_bullet(name):
                clusters.append(name)
            continue
        if line.startswith("|") and "|" in line[1:]:
            cells = [c.strip() for c in line.strip("|").split("|")]
            if cells and not all(set(c) <= set("-: ") for c in cells if c):
                low_cells = [c.strip("`").strip().lower() for c in cells]
                if any(c in ("component", "cluster", "scope", "repo", "asset", "category") for c in low_cells):
                    table_header = low_cells
                    continue
                value_idx = 0
                if table_header:
                    for preferred in ("asset", "component", "cluster", "scope", "repo", "category"):
                        if preferred in table_header:
                            value_idx = table_header.index(preferred)
                            break
                first = cells[value_idx].strip("`").strip() if value_idx < len(cells) else ""
                if first and first.lower() not in (
                    "#", "component", "cluster", "scope", "repo", "asset", "category"
                ):
                    clusters.append(first)
    seen = set()
    out = []
    for c in clusters:
        key = c.lower()
        if key and key not in seen:
            seen.add(key)
            out.append(c)
    return out


def _per_function_coverage_tokens(ws: Path) -> set[str]:
    """Coverage tokens from the per-function hunt inventory.

    `.auditooor/per_function_invariants/manifest.json` records every in-scope
    function the per-function hunt processed (one LLM hunt task per function).
    Each function carries a real `source` path. We tokenize ONLY the path
    segments that DISTINGUISH clusters - i.e. the tail after the directory
    prefix common to every processed function (the repo root). This prevents
    the shared repo-name segment from covering every cluster: a cluster is
    covered iff the hunt processed >=1 function under ITS crate dir; a cluster
    with 0 processed functions stays DARK (honest, no fabricated coverage).
    """
    man = ws / ".auditooor" / "per_function_invariants" / "manifest.json"
    txt = _read_text(man)
    if not txt:
        return set()
    try:
        d = json.loads(txt)
    except (ValueError, json.JSONDecodeError):
        return set()
    rows = d.get("functions") or d.get("records") or d.get("entries") or (
        d if isinstance(d, list) else []
    )
    if not isinstance(rows, list):
        return set()
    # collect cleaned segment-lists per source
    seg_lists: list[list[str]] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        src = r.get("source") or r.get("source_file") or r.get("file") or r.get("path") or ""
        if not isinstance(src, str) or not src.strip():
            continue
        src = src.split(":", 1)[0]
        segs = [x for x in re.split(r"[\\/]+", src) if x]
        if segs:
            seg_lists.append(segs)
    if not seg_lists:
        return set()
    # longest common DIRECTORY prefix across all sources = the repo root; drop it
    common = 0
    shortest = min(len(sl) for sl in seg_lists)
    for i in range(shortest):
        col = {sl[i] for sl in seg_lists}
        if len(col) == 1:
            common = i + 1
        else:
            break
    tokens: set[str] = set()
    for sl in seg_lists:
        for seg in sl[common:]:
            seg = seg.strip().lower()
            if (len(seg) > 2 and seg.replace("-", "").replace("_", "").isalnum()
                    and seg not in ("src", "lib", "mod", "test", "tests", "main")
                    and not seg.endswith(".rs")):
                tokens.add(seg)
    return tokens


def _cluster_brief_tokens(ws: Path) -> set[str]:
    """Coverage tokens sourced from the per-class hunt cluster briefs.

    The per-class hunt writes one markdown brief per SCOPE impact class to
    ``<ws>/.auditooor/hunt_cluster_briefs/<slug>.md`` (e.g.
    ``stealing-or-loss-of-funds.md``). Each brief stem IS the impact-class
    name; its presence evidences that class was hunted. Normalize the stem to
    the same alnum form the cluster matcher uses so the existing
    normalized-substring coverage test matches. Generic across languages -
    the briefs are language-agnostic SCOPE impact-class artifacts.

    <!-- r36-rebuttal: lane L37-RUST-CREDIT registered in .auditooor/agent_pathspec.json -->
    """
    tokens: set[str] = set()
    brief_dir = ws / ".auditooor" / "hunt_cluster_briefs"
    if _exists(brief_dir) and brief_dir.is_dir():
        try:
            for c in brief_dir.iterdir():
                if c.is_file() and c.suffix.lower() == ".md" and not c.name.startswith("."):
                    tokens.add(c.stem.lower())
        except OSError:
            pass
    return {t for t in tokens if t}


def _function_coverage_tokens(ws: Path) -> set[str]:
    """Coverage tokens from the AUTHORITATIVE per-function coverage ledger
    (`.auditooor/function_coverage_completeness.json`), which records every
    in-scope function dispositioned with a real verdict + its source file. The
    older path-token sources dropped FILENAME stems (a `Foo.sol` segment fails
    `.isalnum()` on the dot), so a file-level cluster like `Mailbox.sol` showed
    DARK despite 173/173 function-coverage. Here we emit BOTH the directory
    segments AND the extension-stripped filename stem, so file-level and
    directory-level clusters both match. Generic across languages."""
    fc = ws / ".auditooor" / "function_coverage_completeness.json"
    txt = _read_text(fc)
    if not txt:
        return set()
    try:
        d = json.loads(txt)
    except (ValueError, json.JSONDecodeError):
        return set()
    fns = d.get("functions")
    if not isinstance(fns, list):
        return set()
    tokens: set[str] = set()
    for f in fns:
        if not isinstance(f, dict):
            continue
        fp = str(f.get("file", "")).strip()
        if not fp:
            continue
        for seg in re.split(r"[\\/]+", fp):
            seg = seg.strip().lower()
            if not seg:
                continue
            stem = re.sub(r"\.(sol|rs|go|vy|cairo|move|huff)$", "", seg)
            if (len(stem) > 2
                    and stem.replace("-", "").replace("_", "").replace(".", "").isalnum()
                    and stem not in ("src", "lib", "mod", "test", "tests", "main",
                                     "contracts", "solidity", "source")):
                tokens.add(stem)
    return tokens


def _family_ledger_tokens(ws: Path) -> set[str]:
    """Coverage tokens from the resumable per-family hunt ledger
    (`FAMILY_COVERAGE.md`), which records which in-scope source dirs/files each
    family hunt covered + its result. A cluster ruled out as audited prior-art
    (e.g. `upgrade/` = OZ-standard ProxyAdmin, family 10) is genuinely COVERED by
    the family hunt but emits no function-coverage unit token (OZ-std code is not
    a value-moving unit). Tokenize only PATH-LIKE tokens (`foo/`, `Foo.sol`) from
    the ledger so we credit covered dirs/files without over-crediting on prose."""
    led = ws / "FAMILY_COVERAGE.md"
    txt = _read_text(led)
    if not txt:
        return set()
    tokens: set[str] = set()
    for m in re.finditer(r"([A-Za-z][\w-]{2,})(?:\.sol\b|/)", txt):
        seg = m.group(1).strip().lower()
        if len(seg) > 2 and seg not in ("src", "lib", "contracts", "solidity",
                                        "the", "and", "for", "src", "test"):
            tokens.add(seg)
    return tokens


def _coverage_tokens(ws: Path) -> set[str]:
    tokens: set[str] = set()
    sidecars = ws / "hunt_findings_sidecars"
    alt_sidecars = ws / ".auditooor" / "hunt_findings_sidecars"
    for sc in (sidecars, alt_sidecars):
        if _exists(sc) and sc.is_dir():
            try:
                for c in sc.rglob("*"):
                    if c.is_file() and not c.name.startswith("."):
                        tokens.add(c.stem.lower())
            except OSError:
                pass
    # Skip-set slugs evidence the cluster was at least consulted.
    skip = ws / ".auditooor" / "hunt_skip_set.json"
    txt = _read_text(skip)
    if txt:
        try:
            d = json.loads(txt)
            for e in d.get("entries", []):
                if isinstance(e, dict) and e.get("slug"):
                    tokens.add(str(e["slug"]).lower())
        except (ValueError, json.JSONDecodeError):
            pass
    repo_audit_logs = ws / "repos" / ".audit_logs"
    if _exists(repo_audit_logs) and repo_audit_logs.is_dir():
        try:
            for c in repo_audit_logs.iterdir():
                if c.is_dir() and any(c.iterdir()):
                    tokens.add(c.name.lower())
        except OSError:
            pass
    tokens.update(_external_matrix_tokens(ws))
    tokens.update(_per_function_coverage_tokens(ws))
    tokens.update(_function_coverage_tokens(ws))
    tokens.update(_family_ledger_tokens(ws))
    # r36-rebuttal: lane L37-RUST-CREDIT registered in .auditooor/agent_pathspec.json
    tokens.update(_cluster_brief_tokens(ws))
    return {t for t in tokens if t}


def _is_covered(cluster: str, tokens: set[str]) -> bool:
    cl_norm = re.sub(r"[^a-z0-9]+", "", cluster.lower())
    if not cl_norm:
        return False
    for tok in tokens:
        tok_norm = re.sub(r"[^a-z0-9]+", "", tok)
        if not tok_norm:
            continue
        if cl_norm in tok_norm or tok_norm in cl_norm:
            return True
    return False


def build_matrix(ws: Path) -> tuple[str, list[dict]]:
    clusters = _parse_scope_clusters(ws)
    tokens = _coverage_tokens(ws)
    rows: list[dict] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# HUNT CAPABILITY COVERAGE MATRIX",
        "",
        f"_Generated: {now}_  ",
        f"_Workspace: {ws}_",
        "",
        "One row per in-scope cluster (from SCOPE.md). COVERED = >=1 hunt "
        "sidecar / skip-set / coverage evidence. DARK = no coverage evidence; "
        "DARK rows fail hunt-completeness-check signal (c).",
        "",
        "| Cluster | Status | Evidence |",
        "| --- | --- | --- |",
    ]
    for cl in clusters:
        covered = _is_covered(cl, tokens)
        status = "COVERED" if covered else "DARK"
        evidence = "sidecar/skip-set token match" if covered else "no hunt sidecar or coverage evidence"
        lines.append(f"| {cl} | {status} | {evidence} |")
        rows.append({"cluster": cl, "status": status})
    if not clusters:
        lines.append("| (no clusters parsed from SCOPE.md) | DARK | SCOPE.md absent/empty |")
        rows.append({"cluster": "(none)", "status": "DARK"})
    return "\n".join(lines) + "\n", rows


def run(ws: Path) -> dict:
    matrix_text, rows = build_matrix(ws)
    out_path = ws / MATRIX_NAME
    out_path.write_text(matrix_text, encoding="utf-8")
    dark = [r["cluster"] for r in rows if r["status"] == "DARK"]
    return {
        "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
        "verdict": "pass-matrix-built",
        "reason": f"matrix written ({len(rows)} rows, {len(dark)} DARK)",
        "matrix_path": str(out_path),
        "dark_clusters": dark,
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="capability-coverage-matrix-build.py", description=__doc__)
    p.add_argument("workspace")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not _exists(ws) or not ws.is_dir():
        payload = {"schema": SCHEMA, "gate": GATE, "workspace": str(ws),
                   "verdict": "error", "reason": "workspace not found"}
        print(json.dumps(payload, indent=2) if args.json else f"[{GATE}] verdict=error")
        return 2

    result = run(ws)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{GATE}] verdict={result['verdict']} - {result['reason']}")
        print(f"  matrix: {result['matrix_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
