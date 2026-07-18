#!/usr/bin/env python3
"""per-fn-question-ranker.py - rank per-function hacker questions before MIMO firing.

r36-rebuttal: registered lane per-fn-mimo-upgrade-2026-05-27.

Without ranking, the per-fn pipeline emits ~30K questions per workspace. Firing
all 30K is ~$30 per workspace at MIMO rates and ~70K NOs the operator already
knows from prior reweighter runs. Ranking shrinks the active set to the
highest-signal slice (top 200-500) and recovers all the negative-knowledge
without burning the budget.

Scoring inputs (each is a corpus already on disk):
  1. Function-surface priority (attacker reachability)
     external/payable > public > internal/private
     pure/view = -0.5 (read-only, low impact)
  2. Invariant tier (from invariant_library_index.json)
     tier-1 (real-API verified) > tier-2 (archive) > tier-3 (taxonomy)
  3. Attack-class historical yield (from prior mimo_harness_*/* sidecars)
     attack class with >1% YES rate in prior runs gets +1.0 boost
     attack class with 100% NO rate gets -2.0 penalty
  4. Workspace OOS catalog pre-filter (BUG_BOUNTY.md)
     question matching a numbered OOS row (SE-P*, HB-*, dydx-*) -> hard-zero
  5. KDE filter (reports/known_dead_ends.jsonl)
     question matching a prior dead-end -> hard-zero
  6. Chain-template boost (global_chain_templates.jsonl)
     fn involved in a known compound chain -> +0.5
  7. Scanner-corroboration boost (workspace scan artifacts)
     a slither/aderyn/semgrep/regex/go/cosmos HIGH or CRITICAL hit on the SAME
     (file, function) as the question -> +2.0 (MEDIUM hit -> +0.5). A
     corroborated row is also marked scanner_corroborated=True so it BYPASSES
     the upstream top-30/6-hit truncation (engage.py) and the top-N cap here,
     ensuring a static-analyzer HIGH on a treasury/accounting fn floats into the
     dispatched set instead of being buried at noise priority.

Output: same JSONL schema as input + scoring fields + rank position.
USAGE:
  python3 tools/per-fn-question-ranker.py \
    --questions per_fn_questions.jsonl --workspace ~/audits/<ws> \
    --output ranked.jsonl --top-n 500
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.per_fn_question_ranking.v1"
AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent

# Shared fork-scoped in-scope manifest reader. The ranked per-fn set must be
# intersected with the CURRENT fork-scoped inscope_units.jsonl, else a STALE
# per_fn_hacker_questions.jsonl (generated before the fork-scope prune) leaks
# unmodified-upstream fork files (e.g. bor go-ethereum core/test) into the hunt -
# measured 31% OOS-leak on polygon (83/265 ranked units not in the manifest).
try:
    from tools.lib import scope_exclusion as _scope  # type: ignore
except Exception:  # pragma: no cover - direct-script fallback
    try:
        sys.path.insert(0, str(AUDITOOOR_ROOT / "tools" / "lib"))
        import scope_exclusion as _scope  # type: ignore
    except Exception:
        _scope = None  # type: ignore

# RANK-2 wiring: the structured known-issues registry
# (.auditooor/known_issues.json) was read ONLY by falsification-triage. Make the
# ranker aware of operator-declared acknowledged-OOS issues so a rediscovery
# hard-zeros (verdict 'skip-known-issue-registry') instead of fanning out to a
# paid hunt agent. ADDITIVE - extends the prose-derived OOS catalog. R47/r47-
# rebuttal still governs paste-ready (extension-distinct work is never blocked).
try:
    from tools.lib import known_issues_registry as _ki_registry  # type: ignore
except Exception:  # pragma: no cover - direct-script fallback
    try:
        sys.path.insert(0, str(AUDITOOOR_ROOT / "tools" / "lib"))
        import known_issues_registry as _ki_registry  # type: ignore
    except Exception:
        _ki_registry = None  # type: ignore


class _RegistryOOSPattern:
    """Quacks like a compiled ``re.Pattern`` (``.search`` + ``.pattern``) but is
    tagged as registry-sourced so :func:`score_question` can emit the distinct
    ``skip-known-issue-registry`` verdict. Built from a known-issue's keyword +
    invariant-hint terms (AND-joined, same shape as the prose OOS rows). The
    ``is_registry`` and ``issue_id`` attributes are the only additions over a
    bare pattern, so existing ``p.search(...)`` / ``p.pattern[:60]`` call sites
    work unchanged."""

    is_registry = True

    def __init__(self, issue_id: str, terms: list[str]) -> None:
        self.issue_id = issue_id
        kws = [re.escape(t) for t in terms if t][:5]
        # AND of the (escaped) terms anywhere in the text - mirrors the prose
        # OOS lookahead union so registry rows behave like the existing catalog.
        body = "".join(r"(?=.*" + k + r")" for k in kws) if kws else r"(?!x)x"
        self._re = re.compile(body, re.IGNORECASE)

    def search(self, text: str):
        return self._re.search(text)

    @property
    def pattern(self) -> str:
        return f"known-issue:{self.issue_id}:{self._re.pattern}"


def load_known_issue_oos(ws_path: Path) -> list:
    """Build OOS patterns from the structured known-issues registry. ADDITIVE
    companion to :func:`load_bug_bounty_oos` (prose .md catalog). Returns [] when
    the registry is absent/empty or the shared lib is unavailable."""
    if _ki_registry is None:
        return []
    try:
        terms_by_issue = _ki_registry.oos_keyword_terms(ws_path)
    except Exception:  # pragma: no cover - defensive, never break ranking
        return []
    return [_RegistryOOSPattern(issue_id, terms) for issue_id, terms in terms_by_issue]


def _question_file(q: dict) -> str:
    """Extract the workspace-relative source file from a per-fn question row,
    tolerant of the body-pack (file) and engage (unit_id/source_path) schemas.
    Strips a ::function or :line suffix."""
    v = (q.get("file") or q.get("source_path") or q.get("file_line")
         or q.get("unit_id") or "")
    return str(v).split("::", 1)[0].split(":", 1)[0]


def filter_to_fork_scoped_manifest(questions: list, ws: Path) -> tuple[list, int]:
    """Drop questions that are out-of-scope for the per-fn hunt, two ways:

    1. CATEGORICAL-OOS (belt-and-suspenders): the file is test/mock/generated/
       vendored per the shared classifier. This fires EVEN with no manifest, and
       EVEN when a STALE manifest still lists the file - a manifest built before a
       classifier upgrade (e.g. F5 adding the bor SimulatedBackend `simulated.go`
       test marker) otherwise leaks test scaffolding into the hunt.
    2. NOT-IN-FORK-SCOPED-MANIFEST: when a manifest exists, the file must be one of
       its rows (drops unmodified-upstream fork files the fork-scope prune removed).

    COMPLETENESS-SAFE: no scope lib, or a question with no resolvable file, is KEPT
    (more coverage, never less - the #1 sin is dropping in-scope source). When no
    manifest exists, only the categorical-OOS filter applies (membership unknown ->
    keep). Returns (kept, dropped_count)."""
    if _scope is None:
        return questions, 0
    try:
        inscope = _scope.load_inscope_manifest(ws)
    except Exception:
        inscope = None
    kept, dropped = [], 0
    for q in questions:
        f = _question_file(q)
        if not f:
            kept.append(q)  # cannot judge -> keep (completeness-safe)
            continue
        # (1) categorical OOS by DIRECTORY SHAPE - test/mock/generated/vendored-DIR/
        # scaffolding - applies regardless of manifest presence/staleness. MUST use
        # is_oos_DIR (not is_oos): is_oos treats cosmos-sdk/cometbft/bor as vendored
        # NAME markers and would drop the in-scope FORK files that ARE the audit
        # target (the #1 sin). is_oos_dir drops simulated.go/_mock.go/generated but
        # keeps src/cosmos-sdk/types/coin.go.
        try:
            categorically_oos = _scope.is_oos_dir(f)
        except Exception:
            categorically_oos = False
        if categorically_oos:
            dropped += 1
            continue
        # (2) fork-scoped manifest membership (only when a manifest is present).
        # Path-form-agnostic: questions may carry an ABSOLUTE source_path
        # (<ws>/src/...) while the inscope manifest stores WS-RELATIVE rows
        # ('/src/...'); a bare _norm leaves the absolute path absolute, so a plain
        # membership test drops EVERY in-scope question (measured on etherfi: 200/200
        # dropped -> step-3 zeroed). Match the manifest's form by also testing the
        # ws-relative reduction of the question file before dropping. Completeness-safe:
        # an unresolvable path is NOT dropped here (caught above).
        if inscope:
            nf = _scope._norm(f)
            member = nf in inscope
            if not member:
                try:
                    rel = "/" + Path(f).resolve().relative_to(Path(ws).resolve()).as_posix()
                    member = rel in inscope or rel.lstrip("/") in inscope or _scope._norm(rel) in inscope
                except Exception:
                    member = False
            if not member:
                dropped += 1
                continue
        kept.append(q)
    return kept, dropped


# --- probe_class inference (R80-safe question METADATA, not an attack_class CLAIM) ---
# The coverage-fold producers (auto-coverage-closer / coverage-to-hunt-seed)
# DELIBERATELY emit claim-free questions (no attack_class) - so the mimo yield
# matrix collapses every one to a single "generic" bucket and the reweighter
# cannot learn per-probe-class yield (measured: optimism 290 questions -> 1 bucket).
# probe_class describes WHAT THE QUESTION ASKS (which template/probe generated it),
# NOT a claim that the function has that bug - so stamping it is R80-safe. It splits
# the matrix (optimism 290 -> 14 buckets, 0% generic) so the reweighter can
# deprioritise dead probe-classes and keep productive ones. Vocabulary is reused
# from per-function-hacker-questions.QUESTION_TEMPLATES (no new taxonomy).
_PROBE_REVMAP: list | None = None


def _build_probe_revmap() -> list:
    global _PROBE_REVMAP
    if _PROBE_REVMAP is not None:
        return _PROBE_REVMAP
    rev: list = []
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "pfhq", str(AUDITOOOR_ROOT / "tools" / "per-function-hacker-questions.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        for klass, tpls in getattr(mod, "QUESTION_TEMPLATES", {}).items():
            for t in tpls:
                rx = "^" + re.escape(t).replace(re.escape("{fn}"), ".+").replace(
                    re.escape("{var}"), ".+")
                try:
                    rev.append((re.compile(rx), klass))
                except re.error:
                    pass
    except Exception:
        rev = []
    _PROBE_REVMAP = rev
    return rev


# Keyword fallback for questions whose phrasing diverged from the template.
_PROBE_KEYWORDS = {
    "access-control-missing": ("non-owner", "onlyowner", "privileged", "modifier"),
    "reentrancy": ("reenter", "reentr"),
    "amount-nonzero": ("amount=0", "division by", "wrap"),
    "serialization-roundtrip": ("decode(encode", "non-canonical", "trailing-bytes"),
    "sum-preserved": ("conservation", "sum_over", "invariant"),
    "sig-replay": ("signature", "nonce", "replay"),
}


def infer_probe_class(question_text: str) -> str:
    """Return the probe class a question belongs to (template reverse-match, then
    keyword fallback), or 'generic'. Pure metadata about the question - never a
    claim about the code (R80-safe)."""
    q = question_text or ""
    for rx, klass in _build_probe_revmap():
        if rx.match(q):
            return klass
    low = q.lower()
    for klass, toks in _PROBE_KEYWORDS.items():
        if any(t in low for t in toks):
            return klass
    return "generic"

# Pre-computed historical yield (rolling) — surface_class -> yes_rate
ATTACK_CLASS_PRIOR = {
    "reentrancy": 0.025,
    "access-control-missing": 0.015,
    "sum-preserved": 0.005,
    "amount-nonzero": 0.002,
    "recipient-nonzero": 0.001,
    "deadline-future": 0.001,
    "origin-checked": 0.010,
    "weight-bounded": 0.005,
    "ctx-validation": 0.008,
    "authz": 0.020,
    "generic": 0.001,
}

OOS_PATTERNS_PER_WS = {}  # populated from BUG_BOUNTY.md per workspace


# r36-rebuttal: lane per-fn-mimo-upgrade-2026-05-27 - extending OOS catalog reader for HB PRIOR_CONCERNS.md
def load_bug_bounty_oos(ws_path: Path) -> list[re.Pattern]:
    """Extract OOS phrases from BUG_BOUNTY.md / PRIOR_CONCERNS.md / SRL etc."""
    patterns = []
    for name in ("BUG_BOUNTY.md", "PRIOR_CONCERNS.md", "SRL.md", "SCOPE.md", "SEVERITY.md"):
        f = ws_path / name
        if not f.is_file():
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # r36-rebuttal: lane per-fn-mimo-upgrade-2026-05-27
        # (a) numbered OOS rows: SE-P20 / HB-001 / SRL-6.10 / dydx-known-X
        for m in re.finditer(
            r"(?:SE-P|HB-|dydx-|mezo-|spark-|SRL-)\d+(?:\.\d+)?[:.]?\s*([^\n]{20,200})",
            text,
        ):
            phrase = m.group(1).strip()
            kws = re.findall(r"\b[a-zA-Z][a-zA-Z0-9_]{4,}\b", phrase)
            if len(kws) >= 3:
                patterns.append(re.compile(
                    r"(?=.*\b" + r"\b)(?=.*\b".join(kws[:5]) + r"\b)",
                    re.IGNORECASE,
                ))
        # (b) acknowledged / by-design / known-issue prose
        for m in re.finditer(
            r"(?:acknowledged|by design|out[ -]of[ -]scope|won't fix|wontfix|known issue)[^\n]{20,200}",
            text, re.IGNORECASE,
        ):
            phrase = m.group(0)
            kws = re.findall(r"\b[a-zA-Z][a-zA-Z0-9_]{4,}\b", phrase)
            if len(kws) >= 3:
                patterns.append(re.compile(
                    r"(?=.*\b" + r"\b)(?=.*\b".join(kws[:5]) + r"\b)",
                    re.IGNORECASE,
                ))
    # RANK-2 additive: append OOS patterns synthesized from the structured
    # known-issues registry (.auditooor/known_issues.json). Tagged so a
    # rediscovery hard-zeros with verdict 'skip-known-issue-registry'.
    patterns.extend(load_known_issue_oos(ws_path))
    return patterns


# Reason-bearing field names seen across the KDE store schema variants
# (auditooor.known_dead_end.v1 + legacy). `reason` dominates (1049/1181 rows);
# `kill_reason` (131) is the v1 prose field; the verdict fields are last-resort
# so a row with no prose still contributes a file_line anchor for the skip match.
_KDE_REASON_FIELDS = ("reason", "kill_reason", "kill_verdict", "verdict")
# File-line-bearing field names. `file` carries an optional `:line` suffix
# (e.g. "src/Foo.sol:86"); `evidence_file_line` / `source_path` are the v1 and
# engage-schema variants.
_KDE_FILE_FIELDS = ("file", "evidence_file_line", "source_path")


def _kde_file_line(value: str) -> str:
    """Normalise a KDE/question file (or file:line) value to a comparable key.

    Strips a leading workspace prefix to the path tail (basename + up to two
    parent dirs, matching _norm_scan_file) AND preserves any `:line` /
    `:line,line` suffix so two records pinned to the same file_line collide.
    Returns "" for empty / N/A placeholders (which must never form a join key).
    """
    p = (value or "").strip()
    if not p or p.upper().startswith("N/A"):
        return ""
    # split off the line marker (":86" or ":543,547" or "#27-445")
    m = re.match(r"^(.*?)([:#]\d[\d,\-]*)?$", p)
    base, line = (m.group(1), m.group(2) or "") if m else (p, "")
    base = base.replace("\\", "/").rstrip("/")
    parts = [seg for seg in base.split("/") if seg]
    if not parts:
        return ""
    tail = "/".join(parts[-3:]).lower()
    return tail + line


def load_kde(workspace_name: str) -> list[dict]:  # r36-rebuttal: bugfix-inventory-claude-20260610
    """Load known_dead_ends.jsonl rows for scoped fuzzy + file_line match.

    Returns a list of dicts preserving file, function, file_line, and kill_reason
    so the caller can (a) narrow prose-overlap KDE suppression to the same
    (file, function) pair, (b) skip/demote a question whose file_line matches a
    prior dead-end's file_line (cross-pin), and (c) density-demote a file with
    many prior dead-ends.

    Workspace scoping is RELAXED to a substring/coalesce match so a row pinned to
    a different revision label (e.g. "unknown" or a full audit path) still
    contributes when it names the same workspace. `workspace_name == "any"`
    keeps all rows (legacy contract). Reason and file fields are coalesced across
    the schema variants (`reason` is 8x more common than `kill_reason`).
    """
    kde_path = AUDITOOOR_ROOT / "reports" / "known_dead_ends.jsonl"
    out: list[dict] = []
    if not kde_path.is_file():
        return out
    want = (workspace_name or "").lower().strip()
    with kde_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            row_ws = str(r.get("workspace") or "").lower().strip()
            # Relaxed scope: exact, substring either direction (cross-pin labels),
            # or the catch-all "unknown" bucket. "any" disables scoping.
            if want != "any":
                ws_ok = (
                    row_ws == want
                    or (want and (want in row_ws or row_ws in want))
                    or row_ws == "unknown"
                )
                if not ws_ok:
                    continue
            reason = ""
            for rf in _KDE_REASON_FIELDS:
                v = (r.get(rf) or "")
                if isinstance(v, str) and v.strip():
                    reason = v[:200]
                    break
            file_raw = ""
            for ff in _KDE_FILE_FIELDS:
                v = (r.get(ff) or "")
                if isinstance(v, str) and v.strip():
                    file_raw = v.strip()
                    break
            file_line = _kde_file_line(file_raw)
            fn = (r.get("function") or r.get("contract.function") or "").strip()
            # A row contributes if it carries EITHER a prose reason (for the
            # vocabulary-overlap path) OR a file_line anchor (for the cross-pin
            # skip + density paths). Pure-noise rows (neither) are dropped.
            if reason or file_line:
                out.append({
                    "file": file_raw,
                    "file_line": file_line,
                    "function": fn,
                    "kill_reason": reason.lower(),
                })
    return out


# r36-rebuttal: lane per-fn-mimo-upgrade-2026-05-27 - real schema is member_categories + applicable_function_role_patterns
def load_chain_templates() -> dict[str, list]:
    """global_chain_templates.jsonl indexed by member category / role pattern."""
    p = AUDITOOOR_ROOT / "audit/corpus_tags/derived/global_chain_templates.jsonl"
    out = collections.defaultdict(list)
    if not p.is_file():
        return out
    try:
        with p.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                tid = r.get("chain_template_id") or r.get("chain_id") or r.get("id") or "?"
                cats = r.get("member_categories") or []
                roles = r.get("applicable_function_role_patterns") or []
                # Real chain schema buckets by category + role; index by both
                for k in (cats + roles):
                    if isinstance(k, str) and k:
                        out[k.lower()].append(tid)
                # Also keep old attack_class fallback
                klass = (r.get("attack_class") or r.get("class") or "").lower()
                if klass:
                    out[klass].append(tid)
    except Exception:
        pass
    return out


def load_invariant_index() -> dict:
    """INV id -> verification_tier (best-effort).

    Cross-wire #13: the aggregate invariant_library_index.json often carries NO
    per-record rows (so every anchor_inv defaulted to tier-3 and the tier_score
    signal was dead). Also read the PER-RECORD invariants_extracted*.jsonl
    (invariant_id + verification_tier) so real tiers populate; the aggregate index
    wins on conflict (it is the curated source). Both absent -> empty (legacy)."""
    out = {}
    derived = AUDITOOOR_ROOT / "audit/corpus_tags/derived"
    # Per-record extracted invariants first (broad coverage), aggregate index last
    # (curated, overrides).
    for fname in ("invariants_extracted.jsonl", "invariants_extracted_llm_v1.jsonl"):
        fp = derived / fname
        if not fp.is_file():
            continue
        try:
            for line in fp.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                if isinstance(row, dict):
                    inv_id = row.get("invariant_id") or row.get("inv_id") or row.get("id")
                    tier = row.get("verification_tier")
                    if inv_id and tier:
                        out[inv_id] = tier
        except Exception:
            pass
    p = derived / "invariant_library_index.json"
    if p.is_file():
        try:
            idx = json.loads(p.read_text())
            for row in idx.get("rows", idx.get("items", [])):
                if isinstance(row, dict):
                    inv_id = row.get("inv_id") or row.get("id")
                    tier = row.get("verification_tier", "tier-3-synthetic-taxonomy-anchored")
                    if inv_id:
                        out[inv_id] = tier
        except Exception:
            pass
    return out


# Density-demotion threshold: a question's file with >=K prior dead-ends gets a
# strong negative score so unprivileged value-moving entrypoints outrank
# ruled-out boilerplate (env-overridable; default 3).
def _kde_density_threshold() -> int:
    try:
        v = int(os.environ.get("AUDITOOOR_RANKER_KDE_DENSITY", "3"))
        return v if v >= 1 else 3
    except Exception:
        return 3


# Memoised KDE-derived indexes keyed on the kde_phrases list identity so we build
# the file_line set + per-file-tail density count once, not per question.
_KDE_INDEX_CACHE: dict = {}


def _kde_indexes(kde_phrases: list[dict]) -> dict:
    cache_key = id(kde_phrases)
    cached = _KDE_INDEX_CACHE.get(cache_key)
    if cached is not None and cached[0] is kde_phrases:
        return cached[1]
    file_line_set: set[str] = set()
    density: dict[str, int] = collections.defaultdict(int)
    for e in kde_phrases:
        fl = e.get("file_line") or ""
        if fl:
            file_line_set.add(fl)
            # density keys on the file tail WITHOUT the :line suffix so all
            # dead-ends in one file aggregate.
            file_tail = re.split(r"[:#]\d", fl, maxsplit=1)[0]
            if file_tail:
                density[file_tail] += 1
    idx = {"file_line_set": file_line_set, "density": dict(density)}
    _KDE_INDEX_CACHE.clear()  # only ever cache the most recent list
    _KDE_INDEX_CACHE[cache_key] = (kde_phrases, idx)
    return idx


# Scanner severity -> numeric rank, used to keep the MAX hit per (file, fn).
_SCAN_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}


def _norm_scan_file(path: str) -> str:
    """Strip a trailing :line / #line and any leading workspace prefix.

    Scan artifacts emit either absolute (`/Users/.../src/Foo.sol`) or
    workspace-relative (`contracts/Foo.sol`) paths; the per-fn questions carry a
    workspace-relative or bare `file`. We index by the path tail (basename + up
    to two parent dirs) so the two normalise to a comparable key without a false
    cross-file join. The :line suffix (slither `Foo.sol:27`) is dropped.
    """
    p = (path or "").strip()
    if not p:
        return ""
    # drop slither-style "#27-445" or ":27" trailing line markers
    p = re.split(r"[:#]\d", p, maxsplit=1)[0]
    p = p.replace("\\", "/").rstrip("/")
    parts = [seg for seg in p.split("/") if seg]
    if not parts:
        return ""
    return "/".join(parts[-3:]).lower()


def load_scanner_index(ws_path: Path) -> dict:
    """Build (file_tail, function) -> max scanner severity from scan artifacts.

    Reads the workspace scan artifacts produced by engage.py's scanners:
      - regex_detectors_manifest.json (regex/semgrep-style; carries file+function+severity)
      - .auditooor/go_findings.json   (go detector; function under hit/extra)
      - .auditooor/cosmos_findings.json (cosmos detector; carries function)
      - engage_report.json clusters   (slither/aderyn/glider; file:line only, no
                                        function -> file-level fallback key ("",))
    Returns a dict with two views:
      idx[(file_tail, function)] = "HIGH"    # function-precise corroboration
      file_idx[file_tail]        = "HIGH"    # file-level (slither has no fn)
    Severities kept are the MAX rank seen for that key. Best-effort: a missing or
    malformed artifact is skipped, never raised (R80: only real hits counted).
    """
    idx: dict = {}
    file_idx: dict = {}

    def _record(file_raw: str, fn: str, sev: str):
        sev = (sev or "").strip().upper()
        if sev in ("INFO", "INFORMATIONAL"):
            sev = "LOW"
        if _SCAN_SEV_RANK.get(sev, 0) == 0:
            return
        ftail = _norm_scan_file(file_raw)
        if not ftail:
            return
        # file-level view (always populated)
        if _SCAN_SEV_RANK[sev] > _SCAN_SEV_RANK.get(file_idx.get(ftail, ""), 0):
            file_idx[ftail] = sev
        fn = (fn or "").strip()
        if not fn:
            return
        key = (ftail, fn)
        if _SCAN_SEV_RANK[sev] > _SCAN_SEV_RANK.get(idx.get(key, ""), 0):
            idx[key] = sev

    # 1. regex_detectors_manifest.json (workspace root AND .audit_logs/)
    for rel in ("regex_detectors_manifest.json", ".audit_logs/regex_detectors_manifest.json"):
        f = ws_path / rel
        if not f.is_file():
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for fnd in (data.get("findings") or []):
            if isinstance(fnd, dict):
                _record(str(fnd.get("file") or ""), str(fnd.get("function") or ""),
                        str(fnd.get("severity") or "LOW"))

    # 2. go_findings.json (.auditooor/)
    gf = ws_path / ".auditooor" / "go_findings.json"
    if gf.is_file():
        try:
            data = json.loads(gf.read_text(encoding="utf-8", errors="replace"))
            for _k, pat in (data.get("patterns") or {}).items():
                if not isinstance(pat, dict):
                    continue
                pat_sev = str(pat.get("severity") or "")
                for hit in (pat.get("hits") or []):
                    if not isinstance(hit, dict):
                        continue
                    extra = hit.get("extra") if isinstance(hit.get("extra"), dict) else {}
                    fn = str(hit.get("function") or extra.get("function") or "")
                    _record(str(hit.get("file") or ""), fn,
                            str(hit.get("severity") or pat_sev or "LOW"))
        except Exception:
            pass

    # 3. cosmos_findings.json (.auditooor/ and workspace root)
    for rel in (".auditooor/cosmos_findings.json", "cosmos_findings.json"):
        cf = ws_path / rel
        if not cf.is_file():
            continue
        try:
            data = json.loads(cf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for fnd in (data.get("findings") or []):
            if isinstance(fnd, dict):
                _record(str(fnd.get("file") or ""), str(fnd.get("function") or ""),
                        str(fnd.get("severity") or "MEDIUM"))

    # 4. engage_report.json clusters (slither/aderyn/glider: file:line, no fn)
    er = ws_path / "engage_report.json"
    if er.is_file():
        try:
            data = json.loads(er.read_text(encoding="utf-8", errors="replace"))
            for cl in (data.get("clusters") or []):
                if not isinstance(cl, dict):
                    continue
                for hit in (cl.get("hits") or []):
                    if isinstance(hit, dict):
                        _record(str(hit.get("file_path") or ""), "",
                                str(hit.get("severity") or "LOW"))
        except Exception:
            pass

    return {"idx": idx, "file_idx": file_idx}


def _legacy_glob_yield() -> dict[str, float]:
    """Compute observed yes-rate per attack class by re-globbing prior
    mimo_harness sidecars. Legacy fallback used when the banked
    mimo_observed_yield.json has not been generated yet."""
    counts = collections.defaultdict(lambda: {"yes": 0, "total": 0})
    pattern = AUDITOOOR_ROOT / "audit/corpus_tags/derived/mimo_harness_*"
    for d in glob.glob(str(pattern)):
        for f in glob.glob(d + "/*.json"):
            try:
                sc = json.load(open(f))
                if sc.get("status") != "ok":
                    continue
                body = sc.get("result", "").strip().strip("`").lstrip("json").strip()
                j = json.loads(body)
                if not isinstance(j, dict):
                    continue
                klass = (j.get("attack_class") or "generic").lower()
                applies = j.get("applies_to_target", "no")
                counts[klass]["total"] += 1
                if applies == "yes":
                    counts[klass]["yes"] += 1
            except Exception:
                continue
    out = {}
    for klass, c in counts.items():
        if c["total"] >= 5:
            out[klass] = c["yes"] / c["total"]
    return out


def load_attack_class_yield_observed() -> dict[str, float]:
    """Observed yes-rate per attack class.

    Prefers the banked mimo_observed_yield.json (produced by mimo-corpus-miner)
    so the ranker reads the same pre-aggregated signal the rest of the pipeline
    uses, instead of re-globbing every mimo_harness sidecar on every run. Raw
    yes/total counts are SUMMED across workspaces (not averaging yes_rate) to
    preserve the volume-weighting the legacy glob had, then a >=5 noise floor is
    applied post-aggregation (the ranker's contract has always been >=5; the
    miner's own floor of 3 is intentionally not adopted here).

    Falls through to the legacy per-sidecar glob when the bank is missing,
    unreadable, or aggregates to an empty result, so behavior is preserved
    before the bank has been generated.
    """
    banked = AUDITOOOR_ROOT / "audit/corpus_tags/derived/mimo_observed_yield.json"
    if banked.is_file():
        try:
            data = json.loads(banked.read_text(encoding="utf-8", errors="replace"))
            counts = collections.defaultdict(lambda: {"yes": 0, "total": 0})
            for ws_entry in (data.get("by_workspace") or {}).values():
                if not isinstance(ws_entry, dict):
                    continue
                for klass, c in ws_entry.items():
                    if not isinstance(c, dict):
                        continue
                    counts[klass]["yes"] += int(c.get("yes") or 0)
                    counts[klass]["total"] += int(c.get("total") or 0)
            out = {}
            for klass, c in counts.items():
                if c["total"] >= 5:
                    out[klass] = c["yes"] / c["total"]
            if out:
                return out
        except Exception:
            pass
    return _legacy_glob_yield()


def score_question(q: dict, oos_patterns, kde_phrases, chain_idx, inv_idx,
                   observed_yield, scanner_index=None) -> dict:  # r36-rebuttal: bugfix-inventory-claude-20260610
    """Return q with added score / rank fields."""
    scanner_index = scanner_index or {"idx": {}, "file_idx": {}}
    question_text = q.get("question", "")
    function = q.get("function", "")
    q_file = q.get("file", "")
    fn_class = q.get("question_class", "generic")
    anchor_inv = q.get("anchor_invariant", "")

    # 1. Function-surface priority
    # Read the dedicated fields emitted by the miner; fall back to substring
    # scan of the bare function name only when both fields are absent (legacy).
    callable_surface = q.get("callable_surface", "")
    vis = q.get("function_visibility", "")
    if callable_surface == "external" or "payable" in vis:
        surface_score = 2.0
    elif callable_surface == "external" or vis in ("public", "pub"):
        surface_score = 1.5
    elif "pure" in vis or "view" in vis or callable_surface == "internal":
        # De-prioritise read-only functions; mutating internals keep 1.0 below
        if "pure" in vis or "view" in vis:
            surface_score = -0.5
        else:
            surface_score = 1.0
    elif callable_surface or vis:
        # callable_surface/vis present but unrecognised
        surface_score = 1.0
    else:
        # Legacy fallback: neither field present - scan bare function name
        fn_lower = function.lower()
        if any(k in fn_lower for k in ("payable", "external")):
            surface_score = 2.0
        elif "public" in fn_lower:
            surface_score = 1.5
        elif any(k in fn_lower for k in ("pure", "view")):
            surface_score = -0.5
        else:
            surface_score = 1.0

    # 2. Invariant tier
    inv_tier = inv_idx.get(anchor_inv, "tier-3-synthetic-taxonomy-anchored")
    tier_score = {
        "tier-1-verified-realtime-api": 1.5,
        "tier-1-officially-disclosed": 1.5,
        "tier-2-verified-public-archive": 1.0,
        "tier-3-synthetic-taxonomy-anchored": 0.3,
        "tier-4-bundled-fixture": 0.0,
        "tier-5-quarantine": -2.0,
    }.get(inv_tier, 0.3)

    # 3. Attack-class yield (prefer observed > baked-in prior)
    obs = observed_yield.get(fn_class, ATTACK_CLASS_PRIOR.get(fn_class, 0.001))
    yield_score = obs * 100  # scale 0..0.1 to 0..10

    # 4. OOS pre-filter (hard zero)
    oos_hit = None
    oos_match = None
    for p in oos_patterns:
        if p.search(question_text):
            oos_hit = p.pattern[:60]
            oos_match = p
            break
    if oos_hit:
        # RANK-2: a registry-sourced known-issue match gets a distinct verdict so
        # the loop can route it to a CHEAP extension-distinct confirm (R47/R45/
        # R53) instead of treating it like a generic prose-catalog OOS row.
        is_reg = getattr(oos_match, "is_registry", False)
        return {
            **q,
            "score": 0.0,
            "score_breakdown": {"oos_hit": oos_hit},
            "verdict": "skip-known-issue-registry" if is_reg else "skip-oos-match",
        }

    # 5. KDE filter
    # A KDE record suppresses a question when:
    #   (a) FILE_LINE MATCH (cross-pin): the record's file_line (file tail +
    #       :line suffix) equals the question's file_line. This is the strongest
    #       KDE signal - a prior dead-end pinned to the exact same code location -
    #       and fires regardless of workspace label or prose, so a unit at a
    #       ruled-out file_line is hard-skipped. OR
    #   (b) the record's file+function both match the question's file+function
    #       (exact match; empty fields = wildcard), in which case 4-word overlap
    #       is sufficient; OR
    #   (c) the record has no file+function scope (unscoped / legacy), in which
    #       case the threshold is raised to 6 to avoid common-vocabulary FPs.
    kde_idx = _kde_indexes(kde_phrases)
    # (a) file_line cross-pin skip. Coalesce the question's file/file_line/
    # source_path the same way load_kde coalesces the KDE side.
    q_file_line = ""
    for cand in (q.get("file_line"), q_file, q.get("source_path")):
        q_file_line = _kde_file_line(cand or "")
        if q_file_line:
            break
    if q_file_line and q_file_line in kde_idx["file_line_set"]:
        return {
            **q,
            "score": 0.0,
            "score_breakdown": {"kde_file_line": q_file_line},
            "verdict": "skip-kde-match",
        }

    kde_hit = None
    q_words = set(re.findall(r"\b[a-z]{5,}\b", question_text.lower()))
    for entry in kde_phrases:
        kde_file = entry["file"]
        kde_fn = entry["function"]
        kill_reason = entry["kill_reason"]
        # Determine whether this KDE entry is scoped to the question's fn
        file_match = (not kde_file) or (kde_file == q_file)
        fn_match = (not kde_fn) or (kde_fn == function)
        is_scoped = bool(kde_file or kde_fn)  # at least one field non-empty
        phrase_words = set(re.findall(r"\b[a-z]{5,}\b", kill_reason))
        overlap = len(q_words & phrase_words)
        if file_match and fn_match:
            threshold = 4 if is_scoped else 6
            if overlap >= threshold:
                kde_hit = kill_reason[:60]
                break
    if kde_hit:
        return {
            **q,
            "score": 0.0,
            "score_breakdown": {"kde_hit": kde_hit},
            "verdict": "skip-kde-match",
        }

    # 6. Chain-template boost
    chain_boost = 0.5 if chain_idx.get(fn_class) else 0.0

    # 7a. Scanner-corroboration boost.
    # Join the question's (file, function) to the workspace scan artifacts. A
    # static-analyzer HIGH/CRITICAL on the SAME (file, fn) is the single
    # strongest prior we have that the fn is exploit-relevant, so it gets the
    # largest single boost (+2.0) and marks the row scanner_corroborated so it
    # bypasses the dispatch truncation caps. A function-precise match is
    # preferred; a file-level match (slither/aderyn emit no fn) is a weaker
    # corroboration but still floats accounting/treasury files up.
    ftail = _norm_scan_file(q_file)
    scan_idx = scanner_index.get("idx", {})
    scan_file_idx = scanner_index.get("file_idx", {})
    scanner_sev = ""
    scanner_match = ""
    if ftail and function:
        scanner_sev = scan_idx.get((ftail, function), "")
        if scanner_sev:
            scanner_match = "file+function"
    if not scanner_sev and ftail:
        scanner_sev = scan_file_idx.get(ftail, "")
        if scanner_sev:
            scanner_match = "file-only"
    scanner_boost = 0.0
    scanner_corroborated = False
    if scanner_sev in ("HIGH", "CRITICAL"):
        scanner_boost = 2.0
        scanner_corroborated = True
    elif scanner_sev == "MEDIUM":
        scanner_boost = 0.5

    # 7. Payable-rubric boost. A question whose attack_class maps to a PAYABLE
    # SEVERITY.md row (tagged by per-function-hacker-questions.py from
    # parse_tier_rows), or one emitted as a per-rubric-row targeted question,
    # attacks exactly what THIS program pays for - rank it above a generic
    # rubric-axis question. The boost (3.0) is large enough that a rubric-mapped
    # question outranks a generic one even when the generic one wins surface +
    # tier + yield (max ~2.0 + 1.5 + 10*prior). The targeted-question source
    # gets a small extra nudge so the program's payable rows always surface.
    payable_match = bool(q.get("payable_match"))
    rubric_boost = 0.0
    if payable_match:
        rubric_boost = 3.0
        if q.get("question_source") == "rubric-row-targeted":
            rubric_boost += 0.5

    # 7b. Flow-seeded boost (Bidirectional wiring 49a). A question emitted by the
    # data-flow slice source (per-function-hacker-questions.gen_flow_seeded_questions)
    # is anchored at a REAL unguarded value-moving sink whose UNGUARDED verdict was
    # closure-corrected over the whole inter-procedural slice - a far stronger
    # adversary-reachability prior than a symbol/shape guess. It gets a large
    # additive boost (+4.0) so a real unguarded reachable sink outranks generic
    # shape questions and is on par with / above a payable-rubric match. ADDITIVE:
    # a question without flow_seeded is scored exactly as before (no regression).
    flow_boost = 0.0
    if q.get("flow_seeded") is True or q.get("question_source") == "flow-seeded":
        flow_boost = 4.0

    # 8. KDE density demotion. A question whose FILE accumulated >=K prior
    # dead-ends (env AUDITOOOR_RANKER_KDE_DENSITY, default 3) is in heavily
    # ruled-out territory (e.g. bor cmd/ boilerplate that fired #1-#20 while
    # value-moving entrypoints like claimAsset/buySPOL were dropped). A strong
    # negative penalty (-5.0) sinks it below any fresh in-scope question so the
    # unprivileged value-movers outrank ruled-out boilerplate. A
    # scanner-corroborated row is exempt (a HIGH static hit overrides prior-noise
    # density). Behaviour is identical when no KDE store exists (density empty).
    density_penalty = 0.0
    kde_file_density = 0
    if q_file_line and not scanner_corroborated:
        file_tail = re.split(r"[:#]\d", q_file_line, maxsplit=1)[0]
        kde_file_density = kde_idx["density"].get(file_tail, 0)
        if kde_file_density >= _kde_density_threshold():
            density_penalty = -5.0

    # Cross-wire #8: severity-aware ranking. An impact-methodology question carries
    # an impact_severity_hint (the impact's ceiling tier); boost so Critical/High
    # leads outrank low-ceiling ones in the truncated worklist. Absent hint -> 0
    # (legacy). Mirrors the impact-chain: the classified impact now also steers rank.
    severity_boost = {
        "critical": 2.0, "high": 1.0, "medium": 0.3, "low": 0.0, "informational": 0.0,
    }.get(str(q.get("impact_severity_hint") or "").strip().lower(), 0.0)

    total = (surface_score + tier_score + yield_score + chain_boost
             + scanner_boost + rubric_boost + flow_boost + density_penalty
             + severity_boost)
    return {
        **q,
        "score": round(total, 3),
        "scanner_corroborated": scanner_corroborated,
        "scanner_severity": scanner_sev,
        "score_breakdown": {
            "surface": surface_score,
            "tier": tier_score,
            "yield": round(yield_score, 3),
            "chain_boost": chain_boost,
            "scanner_boost": scanner_boost,
            "scanner_match": scanner_match,
            "rubric_boost": rubric_boost,
            "flow_boost": flow_boost,
            "kde_density_penalty": density_penalty,
            "kde_file_density": kde_file_density,
            "severity_boost": severity_boost,
        },
        "verdict": "rank-eligible",
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--questions", required=True, help="JSONL from per-function-hacker-questions.py")
    p.add_argument("--workspace", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--top-n", type=int, default=500)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    ws = Path(args.workspace)
    ws_name = ws.name

    sys.stderr.write(f"[ranker] loading corpora...\n")
    oos_patterns = load_bug_bounty_oos(ws)
    kde_phrases = load_kde(ws_name)
    chain_idx = load_chain_templates()
    inv_idx = load_invariant_index()
    observed_yield = load_attack_class_yield_observed()
    scanner_index = load_scanner_index(ws)
    sys.stderr.write(f"[ranker] oos_patterns={len(oos_patterns)} kde_rows={len(kde_phrases)} "
                     f"chain_classes={len(chain_idx)} inv_index={len(inv_idx)} "
                     f"observed_classes={len(observed_yield)} "
                     f"scanner_fn_hits={len(scanner_index['idx'])} "
                     f"scanner_file_hits={len(scanner_index['file_idx'])}\n")

    # Read questions, score each
    questions_in = []
    with open(args.questions) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                questions_in.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    sys.stderr.write(f"[ranker] questions_in={len(questions_in)}\n")

    # Fork-scope manifest intersection (loop-fix 2026-06-22): drop units whose
    # file is not in the CURRENT fork-scoped inscope_units.jsonl. A stale per-fn
    # set otherwise burns ~31% of hunt budget on unmodified-upstream fork files
    # (measured on polygon bor). Completeness-safe (no manifest -> keep all).
    questions_in, skipped_fork_scope = filter_to_fork_scoped_manifest(questions_in, ws)
    if skipped_fork_scope:
        sys.stderr.write(f"[ranker] fork-scope manifest filter: dropped {skipped_fork_scope} "
                         f"unit(s) not in inscope_units.jsonl -> {len(questions_in)} kept\n")

    scored = [score_question(q, oos_patterns, kde_phrases, chain_idx, inv_idx,
                              observed_yield, scanner_index) for q in questions_in]

    # Stamp probe_class (R80-safe question metadata) on every ranked record so the
    # mimo yield matrix can key on it instead of collapsing claim-free questions to
    # a single "generic" bucket. Prefers an existing claimed class when present;
    # otherwise infers the probe (template) class from the question text.
    for q in scored:
        q["probe_class"] = (
            q.get("attack_class") or q.get("question_class")
            or infer_probe_class(q.get("question", ""))
        )

    # r36-rebuttal: lane per-fn-mimo-upgrade-2026-05-27
    # Filter zero-score (OOS/KDE matches) + sort descending
    eligible = [q for q in scored if q["verdict"] == "rank-eligible"]
    eligible.sort(key=lambda q: q["score"], reverse=True)

    # Dedupe by (function, class) so top-N is diverse anchors not 200x same fn.
    # The per-function-question rows emitted by engage.py use unit_id/source_path
    # (NO file/function/question_class fields), so keying on (file,function,
    # question_class) collapsed EVERY row to the same ("","","") key -> the whole
    # ranked set became 1 row and step-3's scoped hunt covered 1 unit. Fall back
    # to unit_id/source_path (the per-fn unit identity) + probe_class so each
    # distinct function gets its own anchor. Generic: handles both the body-pack
    # schema (file/function) and the engage per-fn schema (unit_id/source_path).
    seen_fn_class = set()
    deduped = []
    for q in eligible:
        fn_id = (
            q.get("function") or q.get("unit_id")
            or q.get("file") or q.get("source_path") or ""
        )
        file_id = q.get("file") or q.get("source_path") or ""
        cls = q.get("question_class") or q.get("probe_class") or ""
        key = (file_id, fn_id, cls)
        if key in seen_fn_class:
            continue
        seen_fn_class.add(key)
        deduped.append(q)
    sys.stderr.write(f"[ranker] dedup-by-(file,fn,class): {len(eligible)} -> {len(deduped)}\n")

    # Top-N cap with a scanner-corroboration bypass. A row with a HIGH/CRITICAL
    # static-analyzer hit on its (file, fn) is the strongest exploit prior we
    # have, so it must reach the dispatched set even if its composite score
    # places it just below the top-N line. We take the top-N AS USUAL, then
    # append any scanner-corroborated rows that fell outside the cut (their
    # +2.0 boost already lifts most into the cut; this guarantees the tail
    # ones survive the truncation the upstream engage.py top-30/6-hit applies).
    top = deduped[:args.top_n]
    in_top = {id(q) for q in top}
    bypass = [q for q in deduped[args.top_n:] if q.get("scanner_corroborated")
              and id(q) not in in_top]
    if bypass:
        sys.stderr.write(f"[ranker] scanner-corroboration bypass: +{len(bypass)} "
                         f"rows past top-{args.top_n} cap\n")
    top = top + bypass
    for i, q in enumerate(top):
        q["rank"] = i + 1

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        for q in top:
            fh.write(json.dumps(q) + "\n")

    sys.stderr.write(f"[ranker] wrote top {len(top)}/{len(eligible)} eligible "
                     f"({len(scored) - len(eligible)} skipped) to {out_path}\n")

    summary = {
        "schema_version": SCHEMA,
        "questions_in": len(questions_in),
        "skipped_fork_scope": skipped_fork_scope,
        "scored": len(scored),
        "eligible": len(eligible),
        "skipped_oos": sum(1 for q in scored if q["verdict"] == "skip-oos-match"),
        "skipped_known_issue_registry": sum(
            1 for q in scored if q["verdict"] == "skip-known-issue-registry"),
        "skipped_kde": sum(1 for q in scored if q["verdict"] == "skip-kde-match"),
        "scanner_corroborated": sum(1 for q in scored if q.get("scanner_corroborated")),
        "scanner_bypass": len(bypass),
        "top_n": len(top),
        "output": str(out_path),
    }
    if top:
        # Use .get(): older/alternate question producers (unit_id/source_path
        # schema) omit function/question_class, and the summary printer must not
        # KeyError on them.
        summary["top_5"] = [{"rank": q["rank"], "score": q["score"],
                              "function": q.get("function", q.get("unit_id", "?")),
                              "class": q.get("question_class", "?")}
                              for q in top[:5]]
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"questions_in: {summary['questions_in']}")
        print(f"eligible after OOS/KDE filter: {summary['eligible']}")
        print(f"  skipped OOS: {summary['skipped_oos']}")
        print(f"  skipped KDE: {summary['skipped_kde']}")
        print(f"top {summary['top_n']} written to {summary['output']}")
        if "top_5" in summary:
            print("\nTop 5:")
            for r in summary["top_5"]:
                print(f"  #{r['rank']} score={r['score']:.2f} {r['function']} ({r['class']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
