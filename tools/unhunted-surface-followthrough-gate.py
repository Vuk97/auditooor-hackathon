#!/usr/bin/env python3
"""Unhunted-Surface Follow-Through Gate.

# Emits no corpus record.

GENERAL RULE - applies to ANY auditooor workspace, target-agnostic and
language-agnostic. It measures the "follow-through" audit gap class:

  follow-through gap = a surface/pattern WAS flagged (tagged
  "unhunted-surface" / identified-but-no-verdict in the exploit_queue or a
  reports/ triage artifact) but was never driven to a TERMINAL verdict
  (confirmed / refuted / filed / killed / proved). It sits abandoned in a
  non-terminal planning/queued state forever.

Empirical anchor (validation only, lives in the unittest - NOT in this
tool body): IGate.sol::canIncreaseCredit was tagged unhunted-surface in the
morpho-midnight candidate judgment packet, left in state
`ready_for_poc_planning` / proof-readiness `not_claimed` (no terminal
verdict), and the real bug on that surface (the Enter-gate fragile view
reentrancy class) was a prior-audit Medium (TRST-M-2). The surface was
identified by our pipeline but never followed through.

WHAT IT DOES
------------
For a given --workspace, the gate:

  1. Loads the workspace exploit_queue.json (any of several known key
     shapes: queue / entries / candidate_rows / survived_rows) and every
     readable artifact under reports/ and .auditooor/ that may carry
     surface-level triage rows.

  2. Identifies every surface row that is "unhunted-surface" /
     identified-but-no-verdict. Detection is via extensible pattern tables
     (title/tag/state regexes) so it works on JSON queue rows AND on
     markdown triage blocks (e.g. candidate judgment packets).

  3. For each such surface, extracts whatever terminal-verdict signal the
     row carries (proof_status / state / proof_readiness / verdict /
     status). A surface PASSES follow-through only if it carries one of the
     TERMINAL verdict tokens (confirmed / refuted / filed / killed /
     proved / dropped / duplicate ...). A surface FAILS if its only signal
     is a NON-TERMINAL token (ready_for_poc_planning / not_claimed /
     unproved / queued / identified / unhunted ...) or no signal at all.

  4. Emits a verdict + the abandoned-surface list (the follow-through gap).

GENERICITY
----------
  - ZERO hardcoded workspace paths, contract names, function names, or
    finding ids anywhere in this tool body. --workspace drives everything.
  - Language-aware via extensible pattern tables. Defaults cover the
    cross-language surface vocabulary (Solidity ::, Rust ::, Go . / pkg::,
    Move ::, Cairo) because surface rows are textual; the unhunted/terminal
    token tables are language-agnostic and env-extensible.
  - Degrades gracefully: a workspace with no exploit_queue.json and no
    surface artifacts returns pass-no-surfaces (honest empty), not an
    error.

ENV EXTENSION HOOKS (newline- or comma-separated)
  AUDITOOOR_UNHUNTED_TAG_PATTERNS        extra regexes that mark a row as an
                                         unhunted/identified-but-no-verdict
                                         surface.
  AUDITOOOR_UNHUNTED_TERMINAL_TOKENS     extra tokens that count as a
                                         terminal verdict (follow-through
                                         satisfied).
  AUDITOOOR_UNHUNTED_NONTERMINAL_TOKENS  extra tokens that count as
                                         non-terminal (abandoned).
  AUDITOOOR_UNHUNTED_VERDICT_FIELDS      extra JSON field names to read a
                                         verdict signal from.

VERDICT VOCABULARY
  pass-no-workspace-inputs   - no exploit_queue.json and no surface
                               artifacts found (honest empty / graceful).
  pass-no-surfaces           - inputs present but zero unhunted-surface
                               rows identified.
  pass-all-followed-through  - every unhunted-surface row carries a
                               terminal verdict.
  fail-abandoned-surfaces    - >=1 unhunted-surface row lacks a terminal
                               verdict (the follow-through gap). The
                               abandoned list is returned.
  error                      - unexpected failure.

CLI
  unhunted-surface-followthrough-gate.py --workspace <path> [--json]
        [--strict]

  --strict promotes a no-inputs result to a non-zero exit so CI can require
  the gate's inputs to exist.

Exit code: 0 on any pass-*, 1 on fail-abandoned-surfaces (or strict
no-inputs), 2 on error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.source_extensions import SOURCE_EXTS  # noqa: E402  canonical ext registry

SCHEMA = "auditooor.unhunted_surface_followthrough_gate.v1"

# ---------------------------------------------------------------------------
# Pattern tables (env-extensible, target/language-agnostic).
# ---------------------------------------------------------------------------

# A row is an "unhunted surface" if any of these match its title/tag/state.
_DEFAULT_UNHUNTED_TAG_PATTERNS = [
    r"unhunted[\s_-]*surface",
    r"identified[\s_-]*but[\s_-]*no[\s_-]*verdict",
    r"unhunted",
    r"not[\s_-]*yet[\s_-]*hunted",
    r"ready[\s_-]*for[\s_-]*poc[\s_-]*planning",  # queued, never driven
]

# Terminal verdict tokens: presence of any of these means the surface was
# driven to a conclusion (follow-through satisfied). Whole-token matched.
_DEFAULT_TERMINAL_TOKENS = [
    "confirmed",
    "refuted",
    "filed",
    "killed",
    "proved",
    "proven",
    "dropped",
    "duplicate",
    "dupe",
    "rejected",
    "out_of_scope",
    "oos",
    "false_positive",
    "false-positive",
    "paste_ready",
    "paste-ready",
    "accepted",
    "resolved",
    "closed",
    "blocked_prior_disclosure",  # terminal: superseded by external disclosure
    "blocked",
]

# Non-terminal tokens: presence (with NO terminal token) means abandoned.
_DEFAULT_NONTERMINAL_TOKENS = [
    "ready_for_poc_planning",
    "not_claimed",
    "unproved",
    "unhunted",
    "queued",
    "identified",
    "pending",
    "planning",
    "needs_harness",
    "inconclusive",
    "in_progress",
    "todo",
    "open",
]

# JSON field names that may carry a verdict / status signal.
_DEFAULT_VERDICT_FIELDS = [
    "proof_status",
    "state",
    "status",
    "verdict",
    "proof_readiness",
    "readiness",
    "disposition",
    "outcome",
    "terminal_verdict",
    "result",
]

# JSON field names that may carry the surface title / tag text.
_TITLE_FIELDS = [
    "title",
    "name",
    "surface",
    "target",
    "lead_id",
    "id",
    "attack_class",
    "label",
    "summary",
]

# JSON field names that may carry a tag list.
_TAG_FIELDS = ["tags", "labels", "categories", "flags", "blockers"]


def _split_env(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw:
        return []
    parts = re.split(r"[\n,]+", raw)
    return [p.strip() for p in parts if p.strip()]


def _compile_unhunted_patterns() -> list[re.Pattern]:
    pats = list(_DEFAULT_UNHUNTED_TAG_PATTERNS) + _split_env(
        "AUDITOOOR_UNHUNTED_TAG_PATTERNS"
    )
    out = []
    for p in pats:
        try:
            out.append(re.compile(p, re.IGNORECASE))
        except re.error:
            continue
    return out


def _terminal_tokens() -> set[str]:
    toks = set(t.lower() for t in _DEFAULT_TERMINAL_TOKENS)
    toks.update(t.lower() for t in _split_env("AUDITOOOR_UNHUNTED_TERMINAL_TOKENS"))
    return toks


def _nonterminal_tokens() -> set[str]:
    toks = set(t.lower() for t in _DEFAULT_NONTERMINAL_TOKENS)
    toks.update(t.lower() for t in _split_env("AUDITOOOR_UNHUNTED_NONTERMINAL_TOKENS"))
    return toks


def _verdict_fields() -> list[str]:
    fields = list(_DEFAULT_VERDICT_FIELDS)
    fields.extend(_split_env("AUDITOOOR_UNHUNTED_VERDICT_FIELDS"))
    # de-dup, preserve order
    seen = set()
    out = []
    for f in fields:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _token_in(text: str, tokens: set[str]) -> str | None:
    """Whole-token (word-boundary) match of any token in text. Returns the
    matched token or None. Underscores are part of a token, so we match on a
    relaxed boundary that treats run-of [a-z0-9_-] as a single token."""
    low = text.lower()
    for tok in tokens:
        # token may itself contain _ or -; match it as a contiguous unit
        pat = r"(?<![a-z0-9])" + re.escape(tok) + r"(?![a-z0-9])"
        if re.search(pat, low):
            return tok
    return None


# ---------------------------------------------------------------------------
# Surface classification.
# ---------------------------------------------------------------------------


def _classify_verdict(signal_text: str) -> str:
    """Return 'terminal', 'nonterminal', or 'unknown' for a verdict signal."""
    if not signal_text:
        return "unknown"
    term = _token_in(signal_text, _terminal_tokens())
    nonterm = _token_in(signal_text, _nonterminal_tokens())
    # Terminal wins if both present (a row marked killed+queued is killed).
    if term:
        return "terminal"
    if nonterm:
        return "nonterminal"
    return "unknown"


def _is_unhunted_text(text: str, unhunted_pats: list[re.Pattern]) -> bool:
    for p in unhunted_pats:
        if p.search(text):
            return True
    return False


# ---------------------------------------------------------------------------
# JSON queue parsing.
# ---------------------------------------------------------------------------


def _iter_json_rows(queue_obj: Any) -> list[dict]:
    rows: list[dict] = []
    if isinstance(queue_obj, dict):
        for key in ("queue", "entries", "candidate_rows", "survived_rows", "rows"):
            v = queue_obj.get(key)
            if isinstance(v, list):
                rows.extend(r for r in v if isinstance(r, dict))
    elif isinstance(queue_obj, list):
        rows.extend(r for r in queue_obj if isinstance(r, dict))
    return rows


def _row_title(row: dict) -> str:
    parts = []
    for f in _TITLE_FIELDS:
        v = row.get(f)
        if isinstance(v, str):
            parts.append(v)
    for f in _TAG_FIELDS:
        v = row.get(f)
        if isinstance(v, list):
            parts.extend(str(x) for x in v)
        elif isinstance(v, str):
            parts.append(v)
    return " | ".join(parts)


def _row_verdict_signal(row: dict) -> str:
    parts = []
    for f in _verdict_fields():
        v = row.get(f)
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, list):
            parts.extend(str(x) for x in v)
    return " ".join(parts)


def _row_id(row: dict) -> str:
    for f in ("lead_id", "id", "cjp_id", "eq_id"):
        v = row.get(f)
        if isinstance(v, str) and v:
            return v
    return ""


# ---------------------------------------------------------------------------
# Authoritative in-scope value-moving surface universe (function-coverage).
# ---------------------------------------------------------------------------
#
# GENERIC RULE (target-agnostic): the surface-miners that emit
# "unhunted-surface" rows enumerate EVERY function/file - including pure
# leaf-helper decoders (TypedMemView, message-codec libs), OZ-standard
# upgrade/utility contracts (ProxyAdmin, TimelockController,
# ReentrancyGuardTransient), constructors and view getters. None of those are a
# real exploit surface. The authoritative, scope-filtered, R55-leaf-helper-
# filtered, mutation-verified in-scope VALUE-MOVING unit ledger is
# function_coverage_completeness.json (recomputed by its own gate, never hand-
# written - so cross-crediting from it cannot be gamed). A flagged surface is a
# genuine ABANDONED surface only when it maps to a function-coverage unit that
# is in-universe AND not terminally dispositioned. Terminal fc units (already
# hunted to a KILL/refuted/proved verdict) and rows outside the value-moving
# universe (leaf-helpers / OZ-std / non-tracked) are NOT abandoned surfaces.
#
# Falls back to legacy behavior (no cross-credit) when the artifact is absent,
# so a workspace without function-coverage is never silently weakened.

# fc classifications that mean the unit is NOT yet terminally dispositioned.
_FC_NONTERMINAL_CLASS = frozenset(
    {"", "hollow", "untouched", "vacuous", "uncovered", "unhunted", "pending"}
)

# Multi-language source-unit target: `<file>.<ext>::<fn>` or `<file>.<ext>`.
# Covers Solidity AND the Go/Rust/Move/Cairo targets whose fc ledger keys are
# ALSO (file_basename, fn) (function_coverage_completeness.json is language-
# agnostic - NUVA tracks 100 Go units alongside 71 Solidity units). Before this
# generalization the regex was `.sol`-only, so on a Go/Cosmos target every
# non-value-moving Go infra surface (`module.go::ConsensusVersion`,
# `errors.go::Unwrap`) parsed to None and was kept conservatively instead of
# being cross-credited against - and dropped by - the authoritative Go fc
# value-moving ledger.
#
# The extension set is now REGISTRY-SOURCED (lib.source_extensions.SOURCE_EXTS,
# dot-stripped) so a new language is a single registry edit, not a per-tool one.
# This adds Oscript (.oscript/.aa) - an LLM-hunt-only language (no fuzz/static
# engine) whose Obyte AA surfaces (`agent.aa::distribute`) were previously parsed
# to None and never cross-credited, so an oscript surface hunted-to-a-verdict was
# never credited and one still-open was never surfaced as a value-moving gap. No
# registry ext is a prefix of another, so the regex alternation is order-safe.
# Fail-safe: an unrecognised extension still yields None (kept conservatively),
# never a spurious drop.
_UNIT_SRC_EXTS = tuple(e[1:] if e.startswith(".") else e for e in SOURCE_EXTS)
_UNIT_TARGET_RE = re.compile(
    r"([A-Za-z0-9_]+\.(?:" + "|".join(_UNIT_SRC_EXTS) + r"))(?:::([A-Za-z0-9_]+))?"
)


def _load_fc_unit_index(ws: Path) -> tuple[set | None, set | None]:
    """Return (universe, terminal) sets of (file_basename_lower, fn_lower) from
    function_coverage_completeness.json. universe = every tracked in-scope
    value-moving unit; terminal = units with a terminal (non-hollow/untouched)
    disposition. Returns (None, None) when the artifact is absent/unparseable so
    the gate keeps its legacy behavior."""
    fp = ws / ".auditooor" / "function_coverage_completeness.json"
    if not fp.is_file():
        return None, None
    try:
        d = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None, None
    fns = d.get("functions")
    if not isinstance(fns, list):
        return None, None
    universe: set = set()
    terminal: set = set()
    for f in fns:
        if not isinstance(f, dict):
            continue
        fileb = str(f.get("file", "")).split("/")[-1].strip().lower()
        name = str(f.get("name", "")).strip().lower()
        if not fileb or not name:
            continue
        key = (fileb, name)
        universe.add(key)
        cls = str(f.get("classification", "")).strip().lower()
        if cls and cls not in _FC_NONTERMINAL_CLASS:
            terminal.add(key)
    # also fold any explicitly hollow/untouched units back to non-terminal
    hollow = d.get("hollow_or_untouched")
    if isinstance(hollow, list):
        for h in hollow:
            if not isinstance(h, dict):
                continue
            fb = str(h.get("file", "")).split("/")[-1].strip().lower()
            nm = str(h.get("name", "")).strip().lower()
            if fb and nm:
                terminal.discard((fb, nm))
                universe.add((fb, nm))
    return universe, terminal


# Corpus-hunt-fuel lead title shape:
#   "corpus-hunt-fuel: INV-ATM-EX-0003 (reentrancy_atomicity) @ onCSSVTransfer"
# The surface to adjudicate is the (attack_class, target_fn) pair; the INV-* id
# is merely WHICH corpus record suggested it. The corpus-driven-hunt grounds many
# distinct INV-* records onto the same (class, fn), so a single semantic surface
# is generated N times. Counting each INV-* instance as a distinct abandoned
# surface massively over-counts (SSV: 1968 identical crypto_signing@_verifyEBRoots).
_CORPUS_FUEL_SURFACE_RE = re.compile(
    r"corpus-hunt-fuel:.*?\(([a-z_]+)\)\s*@\s*([A-Za-z_]\w*)", re.IGNORECASE
)


def _corpus_fuel_surface_key(title: str) -> tuple | None:
    """Return the semantic surface key (attack_class_lower, fn_lower) for a
    corpus-hunt-fuel lead title, or None for any other title (which dedups by
    (id, title) as before). Used to collapse corpus-record multiplicity to one
    surface per (class, fn) - NOT to hide surfaces: each distinct pair still
    appears once and must reach a terminal verdict."""
    if not title:
        return None
    m = _CORPUS_FUEL_SURFACE_RE.search(title)
    if not m:
        return None
    return (m.group(1).strip().lower(), m.group(2).strip().lower())


def _parse_unit_target(title: str) -> tuple | None:
    """Parse an unhunted-surface title into (file_basename_lower, fn_lower|None).
    Recognises a `<file>.<ext>[::<fn>]` target for any source extension in
    `_UNIT_SRC_EXTS` (Solidity + Go/Rust/Move/Cairo), so the fc value-moving
    cross-credit works on non-Solidity targets. Returns None when no source-unit
    target is present (a non-unit surface the cross-credit cannot classify -
    kept conservatively)."""
    if not title:
        return None
    mt = _UNIT_TARGET_RE.search(title)
    if not mt:
        return None
    fn = (mt.group(2) or "").strip().lower() or None
    return (mt.group(1).strip().lower(), fn)


# A bare mining-OBLIGATION bookkeeping row from the mined-findings-hunter bridge:
# `[obligation:<hash>] <class>: mined_findings_hunter_bridge`. It is a mining
# ledger entry, not an in-scope code surface, and carries NO resolvable unit
# target. We drop it ONLY when it has the obligation tag AND no code-surface
# target of any kind, so a genuine surface that merely references an obligation
# id is never dropped. Generic (no workspace/target names).
_OBLIGATION_TAG_RE = re.compile(r"\[\s*obligation\s*:", re.IGNORECASE)
_ANY_AT_FN_RE = re.compile(r"@\s+([A-Za-z_]\w+)")


def _is_ungrounded_mining_obligation(title: str) -> bool:
    if not title:
        return False
    if not _OBLIGATION_TAG_RE.search(title):
        return False
    # Has a real code-surface target? Then it is grounded - keep it.
    if _parse_unit_target(title) is not None:
        return False
    if _ANY_AT_FN_RE.search(title):
        return False
    return True


_PROD_FN_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)")
_PROD_SKIP_SEG = ("/test/", "/tests/", "/echidna/", "/halmos/", "/mock", "/script/",
                  "/.auditooor/", "/node_modules/", "/lib/", "/out/", "/cache/",
                  "/prior_audits/", "/poc-tests/", "/chimera_harnesses/",
                  "/medusa/", "/foundry/", "/poc_execution/")


def _production_fn_names(ws: Path) -> set[str]:
    """Set of function names DEFINED in production source (contracts/src .sol),
    excluding test / echidna / mock / script / mutant files. A fn-only
    corpus-hunt-fuel lead whose fn is NOT a production fn (e.g. echidna
    `action_*` / `_boundAmount`, defined only under test/echidna/) is TEST code,
    not a real abandoned surface. Keeps internal production helpers (e.g.
    `_verifyEBRoots`) and interface declarations (resolved by the ledger)."""
    names: set[str] = set()
    try:
        sol_files = list(ws.rglob("*.sol"))
    except OSError:
        return names
    for p in sol_files:
        rel = "/" + str(p).replace("\\", "/").lower()
        if any(seg in rel for seg in _PROD_SKIP_SEG):
            continue
        if p.name.endswith((".t.sol", ".s.sol")) or "mutant" in p.name.lower():
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _PROD_FN_RE.finditer(txt):
            names.add(m.group(1).lower())
    return names


def _fc_credit_filter(
    abandoned: list[dict], universe: set, terminal: set,
    production_fn_names: set | None = None,
) -> tuple[list[dict], int, int]:
    """Drop abandoned rows that are NOT genuine in-scope value-moving gaps,
    cross-credited from the authoritative function-coverage unit ledger.

    A row is KEPT (genuine abandoned surface) only when it maps to >=1 fc unit
    that is in-universe and NOT terminal. Rows mapping to a terminal unit (hunted
    to a verdict) or to no in-universe value-moving unit (leaf-helper / OZ-std /
    untracked) are dropped. Non-unit rows (no `*.sol`) are kept conservatively.

    Returns (kept_rows, dropped_terminal, dropped_out_of_universe)."""
    nonterminal_units = universe - terminal
    nonterminal_files = {f for (f, _) in nonterminal_units}
    # fn-NAME views of the unit ledger, for fn-only titles (corpus-hunt-fuel leads
    # are titled `... @ <fn>` with NO file). Resolving the fn against the fc
    # universe lets us drop a fn that exists ONLY in a test/harness file (e.g.
    # echidna `action_*` / `_boundAmount`) - it is not a production unit, so it is
    # not a genuine abandoned surface. Without this they were kept conservatively
    # and inflated the abandoned count with harness code (the SSV `_verifyEBRoots`
    # vs `action_cross_cluster_proof_replay` split). Generic + fail-safe.
    _fn_only_re = re.compile(r"@\s+([A-Za-z_]\w+)")
    # Unambiguous echidna/medusa/forge HARNESS function-name conventions. A
    # fn-only `@ <fn>` corpus-hunt-fuel lead whose fn is a harness action/property
    # is TEST code, never a production abandoned surface (the SSV
    # `action_cross_cluster_proof_replay` / `echidna_*` flood). Conservative: only
    # these explicit prefixes drop; interface-declared / internal / production fns
    # are left for the ledger to resolve (preserves the morpho interface-surface
    # behavior).
    _HARNESS_FN_RE = re.compile(r"^(action_|echidna_|property_|invariant_|medusa_|fuzz_|test_|setup$|setupactors)")
    kept: list[dict] = []
    dropped_terminal = 0
    dropped_oou = 0
    for r in abandoned:
        key = _parse_unit_target(r.get("title", ""))
        if key is None:
            # No *.sol target. Drop ONLY unambiguous harness fns from an fn-only
            # `@ <fn>` title; keep everything else (ledger resolves interface /
            # production surfaces).
            m = _fn_only_re.search(r.get("title", "") or "")
            if m:
                fn_only = m.group(1).strip().lower()
                # Drop if it is an unambiguous harness fn, OR (when we know the
                # production fn set) a fn NOT defined in production source - both
                # are test/non-production, not real abandoned surfaces. Production
                # fns (incl internal helpers + interface decls) are KEPT for the
                # ledger / a real hunt to resolve.
                if _HARNESS_FN_RE.match(fn_only) or (
                    production_fn_names and fn_only not in production_fn_names
                ):
                    dropped_oou += 1
                    continue
            kept.append(r)  # production / unclassifiable non-unit surface - keep
            continue
        fb, fn = key
        if fn is not None:
            if (fb, fn) in nonterminal_units:
                kept.append(r)  # in-universe, not yet terminal => genuine gap
            elif (fb, fn) in terminal:
                dropped_terminal += 1
            else:
                dropped_oou += 1  # not a tracked value-moving unit
        else:
            # file-level surface: a gap only if the file has an uncovered unit
            if fb in nonterminal_files:
                kept.append(r)
            elif any(f == fb for (f, _) in terminal):
                dropped_terminal += 1
            else:
                dropped_oou += 1  # file has no tracked value-moving unit
    return kept, dropped_terminal, dropped_oou


def scan_json_queue(path: Path, unhunted_pats: list[re.Pattern]) -> list[dict]:
    """Return abandoned-surface records found in a JSON queue file."""
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    abandoned = []
    for row in _iter_json_rows(obj):
        title = _row_title(row)
        if not _is_unhunted_text(title, unhunted_pats):
            continue
        signal = _row_verdict_signal(row)
        verdict_class = _classify_verdict(signal)
        if verdict_class != "terminal":
            abandoned.append(
                {
                    "source": str(path),
                    "id": _row_id(row),
                    "title": (title[:200] if title else "(untitled)"),
                    "verdict_signal": signal.strip()[:200] or "(none)",
                    "verdict_class": verdict_class,
                }
            )
    return abandoned


# ---------------------------------------------------------------------------
# Markdown / text triage-block parsing.
# ---------------------------------------------------------------------------

# Block delimiter: a markdown heading (### ...) starts a new triage block.
_HEADING_RE = re.compile(r"^#{1,6}\s+(.*)$")

# r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered in .auditooor/agent_pathspec.json
# Generic document-structure headings that are CONTAINERS (aggregating the real
# leads listed individually elsewhere), not surfaces themselves.
_STRUCTURAL_HEADINGS = frozenset({
    "rows", "summary", "state summary", "packets", "inputs", "outputs",
    "notes", "table", "results", "contents", "overview", "index", "totals",
})


def scan_markdown_blocks(path: Path, unhunted_pats: list[re.Pattern]) -> list[dict]:
    """Split a markdown/text artifact into heading-delimited blocks; for each
    block that is an unhunted surface, check whether it carries a terminal
    verdict token anywhere in the block."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    lines = text.splitlines()
    # Build blocks: each block = (heading_line, body_lines)
    blocks: list[tuple[str, list[str]]] = []
    cur_head = ""
    cur_body: list[str] = []
    for ln in lines:
        m = _HEADING_RE.match(ln)
        if m:
            if cur_head or cur_body:
                blocks.append((cur_head, cur_body))
            cur_head = ln
            cur_body = []
        else:
            cur_body.append(ln)
    if cur_head or cur_body:
        blocks.append((cur_head, cur_body))

    abandoned = []
    for head, body in blocks:
        block_text = head + "\n" + "\n".join(body)
        if not _is_unhunted_text(block_text, unhunted_pats):
            continue
        verdict_class = _classify_verdict(block_text)
        if verdict_class == "terminal":
            continue
        # r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered in .auditooor/agent_pathspec.json
        # Skip a bare STRUCTURAL section heading (a document container like
        # `## Rows` / `## Summary` whose body merely lists/aggregates the real
        # leads, which are counted individually from the JSON queue). Such a
        # block has a one-word generic heading and carries no lead identity of
        # its own - counting it is a granularity false-positive.
        head_title = head.lstrip("# ").strip()
        if head_title.lower() in _STRUCTURAL_HEADINGS:
            continue
        # Extract a title for reporting (first 'Title:' line or the heading)
        title = head.lstrip("# ").strip()
        for bl in body:
            tm = re.match(r"\s*-?\s*Title:\s*(.+)", bl, re.IGNORECASE)
            if tm:
                title = tm.group(1).strip()
                break
        # Extract id from heading if present (e.g. 'CJP-075 - EQ-566')
        rid = ""
        idm = re.search(r"\b([A-Z]{2,}-[A-Za-z0-9]+)\b", head)
        if idm:
            rid = idm.group(1)
        # Capture the strongest non-terminal signal line for evidence
        sig = ""
        sig_pat = re.compile(
            r"(State|Proof readiness|Status|Verdict|Disposition):\s*`?([^`\n]+)",
            re.IGNORECASE,
        )
        sm = sig_pat.search(block_text)
        if sm:
            sig = f"{sm.group(1)}: {sm.group(2).strip()}"
        abandoned.append(
            {
                "source": str(path),
                "id": rid,
                "title": title[:200] if title else "(untitled)",
                "verdict_signal": sig[:200] or "(non-terminal / none)",
                "verdict_class": verdict_class,
            }
        )
    return abandoned


# ---------------------------------------------------------------------------
# Evidence-grounded terminal-verdict ledger.
# ---------------------------------------------------------------------------

_LEDGER_REL = (".auditooor", "unhunted_terminal_verdicts.json")
_LEDGER_TERMINAL = {"refuted", "confirmed", "filed", "killed", "proved"}


# r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered in .auditooor/agent_pathspec.json
def _apply_terminal_verdict_ledger(ws: Path, abandoned: list[dict]) -> tuple[int, list[dict]]:
    """Remove leads that carry a valid evidence-grounded terminal verdict.

    A ledger entry counts ONLY when (a) its verdict is a terminal token and
    (b) its evidence_ref resolves to a real file under the workspace. This makes
    the credit impossible to fake without a real cited artifact. Returns
    (resolved_count, still_abandoned)."""
    led = ws / _LEDGER_REL[0] / _LEDGER_REL[1]
    if not led.is_file():
        return 0, abandoned
    try:
        data = json.loads(led.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return 0, abandoned
    verdicts = data.get("verdicts") if isinstance(data, dict) else None
    if not isinstance(verdicts, list):
        return 0, abandoned
    by_id: dict[str, dict] = {}
    by_title: dict[str, dict] = {}
    for v in verdicts:
        if not isinstance(v, dict):
            continue
        if str(v.get("verdict", "")).lower() not in _LEDGER_TERMINAL:
            continue
        ref = str(v.get("evidence_ref", "")).strip()
        if not ref:
            continue
        # r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered in .auditooor/agent_pathspec.json
        # HONESTY (coverage-theater fix): reject a verdict whose evidence_ref is
        # the SHARED source-unit coverage artifact (coverage_report.json). A
        # single shared file cannot be N distinct terminal verdicts - source-unit
        # coverage proves a unit appeared in a heatmap, NOT that a per-fn exploit
        # oracle drove THIS surface to a terminal conclusion. Such a verdict
        # leaves the lead abandoned so the gate honestly reflects the undriven
        # long tail.
        if Path(ref).name == "coverage_report.json":
            continue
        # evidence_ref must resolve to a real file under the workspace
        cand = (ws / ref) if not os.path.isabs(ref) else Path(ref)
        if not cand.is_file():
            continue
        if v.get("lead_id"):
            by_id[str(v["lead_id"])] = v
        if v.get("title"):
            by_title[str(v["title"])] = v
    if not by_id and not by_title:
        return 0, abandoned
    kept: list[dict] = []
    resolved = 0
    for lead in abandoned:
        lid = str(lead.get("id", ""))
        ltitle = str(lead.get("title", ""))
        if (lid and lid in by_id) or (ltitle and ltitle in by_title):
            resolved += 1
            continue
        kept.append(lead)
    return resolved, kept


# ---------------------------------------------------------------------------
# Workspace orchestration.
# ---------------------------------------------------------------------------

_TEXT_EXTS = {".md", ".txt", ".jsonl"}
_SKIP_DIR_NAMES = {".git", "node_modules", "target", "out", "cache", "lib"}

# Agent PROMPT / INPUT directories under .auditooor/. Their .md files are briefs
# and skeleton templates fed INTO a hunt - they quote the surface/skeleton
# vocabulary (`ready_for_poc_planning`, `unhunted-surface`, R42/R45 skeletons) as
# TEMPLATE text, so scanning them re-flags the prompt itself as an abandoned
# surface (a self-scan false-positive). A dispatch brief is an input, never a
# triage OUTPUT that drives a surface to a verdict; exclude these prompt dirs.
_SKIP_PROMPT_DIR_NAMES = {"dispatch_briefs", "dispatch_brief", "spawn-worker-pathspec",
                          "hunt_prompts"}  # agent worklist/brief inputs, not triage surfaces
# Disposition-NOTE filename markers: a file whose PURPOSE is to record refutations /
# terminal verdicts is not itself an open surface. Skipping it (by name) avoids the
# self-reference false-positive where a refutation write-up is re-read as an unhunted
# surface because it quotes a non-terminal token (Strata 2026-07-07: an 11-lead
# followthrough batch + a rubric-class refutation .md both mis-counted).
_DISPOSITION_NOTE_MARKERS = ("refutation", "_dispositions", "terminal_verdict",
                             "_adjud", "disposition_note")


def _ledger_evidence_paths(ws: Path) -> set:
    """Absolute paths of every evidence_ref cited in the terminal-verdict ledger.

    A disposition-evidence artifact (e.g. a refutation .md that NAMES the surfaces it
    closes) lives under .auditooor/ and textually matches the unhunted/unattempted
    detection patterns, so the scan re-flags it as a NEW abandoned surface - a
    self-referential false-positive (strata 2026-07-01: the rubric-class refutation
    note cited by 5 verdicts re-appeared as 1 abandoned surface). Evidence the ledger
    points at is BY DEFINITION dispositioned, not an open surface; exclude it."""
    out: set = set()
    led = ws / _LEDGER_REL[0] / _LEDGER_REL[1]
    if not led.is_file():
        return out
    try:
        data = json.loads(led.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return out
    for v in (data.get("verdicts") or []) if isinstance(data, dict) else []:
        ref = str((v or {}).get("evidence_ref", "")).strip() if isinstance(v, dict) else ""
        if not ref:
            continue
        cand = Path(ref) if os.path.isabs(ref) else (ws / ref)
        try:
            out.add(str(cand.resolve()))
        except (OSError, ValueError):
            out.add(str(cand))
    return out


def _candidate_artifacts(ws: Path) -> tuple[list[Path], list[Path]]:
    """Return (json_queue_paths, text_artifact_paths)."""
    json_paths: list[Path] = []
    text_paths: list[Path] = []

    eq = ws / ".auditooor" / "exploit_queue.json"
    if eq.is_file():
        json_paths.append(eq)

    evidence_paths = _ledger_evidence_paths(ws)
    for sub in (ws / "reports", ws / ".auditooor"):
        if not sub.is_dir():
            continue
        for p in sorted(sub.rglob("*")):
            if not p.is_file():
                continue
            if any(part in _SKIP_DIR_NAMES for part in p.parts):
                continue
            if any(part in _SKIP_PROMPT_DIR_NAMES for part in p.parts):
                continue  # agent prompt/input brief, not a triage output
            if p == eq:
                continue
            # A disposition-NOTE artifact (its name marks it as a refutation /
            # terminal-verdict write-up) is not an open surface - skip it so a
            # refutation doc is never re-read as an abandoned surface.
            _pl = p.name.lower()
            if any(m in _pl for m in _DISPOSITION_NOTE_MARKERS):
                continue
            # A prose disposition-NOTE (.md/.txt) cited by the ledger is not an open
            # surface - skip it to avoid the self-reference false-positive. Restrict to
            # prose suffixes: a .json/.jsonl evidence_ref may be a SHARED surface-bearing
            # queue (e.g. exploit_queue.json) whose individual rows are resolved per-id,
            # so the whole file must still be scanned.
            if p.suffix in {".md", ".txt"}:
                try:
                    if str(p.resolve()) in evidence_paths:
                        continue
                except (OSError, ValueError):
                    pass
            if p.suffix == ".json":
                json_paths.append(p)
            elif p.suffix in _TEXT_EXTS:
                text_paths.append(p)
    return json_paths, text_paths


# r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered in .auditooor/agent_pathspec.json
def evaluate(workspace: str, *, apply_ledger: bool = True) -> dict:
    # apply_ledger=False returns the RAW abandoned list (pre terminal-verdict
    # ledger) - the adjudicator MUST use this so it classifies every surface
    # from scratch and never shrinks its own ledger on re-run.
    ws = Path(workspace).expanduser().resolve()
    if not ws.is_dir():
        return {
            "schema": SCHEMA,
            "workspace": str(ws),
            "verdict": "error",
            "error": f"workspace not a directory: {ws}",
            "abandoned_surfaces": [],
            "stats": {},
        }

    unhunted_pats = _compile_unhunted_patterns()
    json_paths, text_paths = _candidate_artifacts(ws)

    if not json_paths and not text_paths:
        return {
            "schema": SCHEMA,
            "workspace": str(ws),
            "verdict": "pass-no-workspace-inputs",
            "abandoned_surfaces": [],
            "stats": {
                "json_artifacts_scanned": 0,
                "text_artifacts_scanned": 0,
                "unhunted_surfaces_found": 0,
                "abandoned_count": 0,
            },
        }

    abandoned: list[dict] = []
    # De-dup by (id, title) so the same surface in queue + packet is one row.
    seen_keys: set = set()

    def _add(records: list[dict]) -> None:
        for r in records:
            # Corpus-hunt-fuel grounds MANY corpus records (distinct INV-* ids)
            # onto the SAME (attack_class, target_fn) - that is ONE surface to
            # adjudicate, not N. Dedup such rows by their SEMANTIC surface key so
            # 1968 `crypto_signing @ _verifyEBRoots` leads (one per corpus record)
            # count as a single surface. Non-corpus-fuel rows keep (id,title)
            # dedup. This NEVER hides an unadjudicated surface - each distinct
            # (class,fn) still appears once and must reach a terminal verdict.
            cf = _corpus_fuel_surface_key(r.get("title", ""))
            key = ("corpus-fuel", cf[0], cf[1]) if cf is not None else (
                r.get("id", ""), r.get("title", "")
            )
            if key in seen_keys:
                continue
            seen_keys.add(key)
            abandoned.append(r)

    for jp in json_paths:
        _add(scan_json_queue(jp, unhunted_pats))
    for tp in text_paths:
        _add(scan_markdown_blocks(tp, unhunted_pats))

    # Drop UNGROUNDED corpus-hunt-fuel leads: a corpus record that did not ground
    # to any in-scope function (title carries no `(class) @ <fn>` target, e.g.
    # "... (general) no in-target fn") is NOT a code surface in this workspace -
    # it is a corpus hypothesis that found no home (commonly a cross-language /
    # cross-engagement record: a Move `move_resource_model` or Go/Rust invariant
    # has no Solidity applicability). It is not a huntable surface, so it is not an
    # abandoned one. A corpus-fuel lead that DID ground (has `@ <fn>`) is KEPT and
    # must still reach a terminal verdict. Generic + fail-safe (only drops corpus-
    # hunt-fuel titles with no grounded fn).
    ungrounded_corpus_fuel = 0
    _kept_after_ungrounded: list[dict] = []
    for r in abandoned:
        t = r.get("title", "") or ""
        if t.lower().lstrip().startswith("corpus-hunt-fuel:") and _corpus_fuel_surface_key(t) is None:
            ungrounded_corpus_fuel += 1
            continue
        # Drop a bare MINING-OBLIGATION bookkeeping row: title shaped
        # `[obligation:<hash>] <class>: <hunter-bridge-source>` with NO grounded
        # code surface (no `<file>.<ext>`, no `@ <fn>`, no `::<fn>`). These are
        # mined-findings-hunter-bridge obligation records - a mining ledger entry,
        # not an in-scope code surface to hunt. Requires BOTH the `[obligation:]`
        # tag AND the absence of any resolvable unit target, so a real surface
        # that merely mentions an obligation id is never dropped.
        if _is_ungrounded_mining_obligation(t):
            ungrounded_corpus_fuel += 1
            continue
        _kept_after_ungrounded.append(r)
    abandoned = _kept_after_ungrounded

    # r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered in .auditooor/agent_pathspec.json
    # Evidence-grounded terminal-verdict ledger: a lead that
    # unhunted-surface-adjudicate.py drove to a `refuted` verdict with a
    # source-cited evidence_ref is terminal. We re-validate the evidence_ref
    # resolves to a REAL file under the workspace, so a fabricated ledger cannot
    # green the gate (anti-false-green). Leads with no ledger verdict stay
    # abandoned - a genuine gap is never hidden.
    # r36-rebuttal: lane FIX-UNHUNTED-ADJUDICATE registered in .auditooor/agent_pathspec.json
    resolved_by_ledger = 0
    if apply_ledger:
        resolved_by_ledger, abandoned = _apply_terminal_verdict_ledger(ws, abandoned)

    # Cross-credit the authoritative function-coverage value-moving unit ledger
    # AFTER the evidence-grounded terminal-verdict ledger (which is the more
    # specific, evidence-cited resolution). Drops rows mapping to a terminally-
    # hunted unit or to no tracked value-moving unit (leaf-helper / OZ-std /
    # view-getter); keeps genuine in-universe-non-terminal gaps. Applies in both
    # ledger modes so the adjudicator (apply_ledger=False) never wastes effort
    # adjudicating non-surfaces.
    fc_universe, fc_terminal = _load_fc_unit_index(ws)
    fc_dropped_terminal = 0
    fc_dropped_out_of_universe = 0
    if fc_universe is not None:
        abandoned, fc_dropped_terminal, fc_dropped_out_of_universe = _fc_credit_filter(
            abandoned, fc_universe, fc_terminal, _production_fn_names(ws)
        )

    abandoned.sort(key=lambda r: (r.get("source", ""), r.get("id", ""), r.get("title", "")))

    stats = {
        "json_artifacts_scanned": len(json_paths),
        "text_artifacts_scanned": len(text_paths),
        "unhunted_surfaces_found": len(abandoned),  # only abandoned are kept
        "abandoned_count": len(abandoned),
        "resolved_by_ledger": resolved_by_ledger,
        "fc_dropped_terminal": fc_dropped_terminal,
        "fc_dropped_out_of_universe": fc_dropped_out_of_universe,
        "ungrounded_corpus_fuel_dropped": ungrounded_corpus_fuel,
    }

    if not abandoned:
        verdict = "pass-no-surfaces"
    else:
        verdict = "fail-abandoned-surfaces"

    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "verdict": verdict,
        "abandoned_surfaces": abandoned,
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _print_human(result: dict) -> None:
    v = result["verdict"]
    print(f"[unhunted-surface-followthrough-gate] verdict: {v}")
    print(f"  workspace: {result['workspace']}")
    st = result.get("stats", {})
    if st:
        print(
            "  scanned: {j} json + {t} text artifacts; abandoned: {a}".format(
                j=st.get("json_artifacts_scanned", 0),
                t=st.get("text_artifacts_scanned", 0),
                a=st.get("abandoned_count", 0),
            )
        )
    if result.get("error"):
        print(f"  error: {result['error']}")
    abandoned = result.get("abandoned_surfaces", [])
    if abandoned:
        print(f"  ABANDONED UNHUNTED SURFACES ({len(abandoned)}) - no terminal verdict:")
        for r in abandoned[:200]:
            rid = r.get("id") or "-"
            print(f"    [{rid}] {r.get('title','')}")
            print(
                f"        signal: {r.get('verdict_signal','')} "
                f"(class={r.get('verdict_class','')})"
            )
            print(f"        source: {r.get('source','')}")
        if len(abandoned) > 200:
            print(f"    ... and {len(abandoned) - 200} more")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Unhunted-Surface Follow-Through Gate (follow-through audit gap)."
    )
    ap.add_argument("--workspace", required=True, help="Path to the audit workspace.")
    ap.add_argument("--json", action="store_true", help="Emit JSON.")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="Treat pass-no-workspace-inputs as a non-zero exit.",
    )
    args = ap.parse_args(argv)

    try:
        result = evaluate(args.workspace)
    except Exception as exc:  # pragma: no cover - defensive
        result = {
            "schema": SCHEMA,
            "workspace": args.workspace,
            "verdict": "error",
            "error": f"{type(exc).__name__}: {exc}",
            "abandoned_surfaces": [],
            "stats": {},
        }

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_human(result)

    v = result["verdict"]
    if v == "error":
        return 2
    if v == "fail-abandoned-surfaces":
        return 1
    if v == "pass-no-workspace-inputs" and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
