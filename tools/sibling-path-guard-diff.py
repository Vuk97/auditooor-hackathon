#!/usr/bin/env python3
"""sibling-path-guard-diff.py - proactive sibling-path guard-asymmetry detector.

Background
----------
The L30 missing-guard-callsite-enumerator
(``tools/missing-guard-callsite-enumerator.sh``) is REACTIVE: the operator
already suspects a specific ``(guard, resource)`` pair and asks the tool to
enumerate the call sites that touch ``resource`` but skip ``guard``. That
relies on the operator first *guessing* the right pair.

This tool PRODUCTIONIZES that subtraction core into a PROACTIVE sweep. It
walks the whole in-scope source tree, auto-enumerates sibling code-path
PAIRS that SHOULD share an invariant, diffs the guard set each path applies,
and flags asymmetries where a guard present on path A is absent (or
under-implemented) on its sibling path B.

The canonical empirical anchor is Hyperbridge's FaultDisputeGame path
enforcing ``verify_not_challenged`` while the sibling L2Oracle path enforced
zero analogous guard (an asymmetric in-tree guard = direct evidence the
project INTENDED the check). The reactive L30 tool could only find that if
the operator already knew to look; this tool finds it by sweeping the tree.

Two complementary pairing strategies:

(1) Naming-convention pairs - functions whose names match the L30 sibling
    pair list (deposit/withdraw, mint/burn, claim/finalize, supply/borrow,
    propose/execute, lock/unlock, escrow/release, vote/tally, sender/
    receiver, plus a few common extras). The two arms of such a pair
    almost always share an invariant (the same resource is moved in
    opposite directions, gated by the same access / state / bounds check).

(2) Variant-arm pairs - sibling implementations of the SAME logical
    handler: Rust ``impl Trait for TypeA`` vs ``impl Trait for TypeB`` of
    the same trait method, Solidity functions of the same name across
    sibling contracts, Go methods of the same name across sibling types.
    These are the FDG-vs-L2Oracle shape: two verifiers that should enforce
    the same defense.

For each discovered pair the tool greps each arm's body for guard-like
calls (``require`` / ``revert`` / ``assert`` / ``ensure_*`` / ``verify_*``
/ ``onlyX`` modifiers / ``check_*`` / ``validate*`` / panic-class), builds
the guard SET per arm, and SUBTRACTS: a guard in A but not in B (and vice
versa) is an asymmetry row. The subtraction is exactly the L30
GUARDED/UNGUARDED core, generalized from one operator-supplied pair to
every auto-discovered pair.

Language awareness covers Solidity (.sol), Rust (.rs), and Go (.go) - the
three languages the L30 enumerator already supports plus a generic
fallback. Function-body extraction is brace/indent aware per language so
the guard set is scoped to the arm, not the whole file.

Output
------
``<ws>/.auditooor/sibling_guard_asymmetries.jsonl`` - one JSON object per
flagged asymmetry, schema ``auditooor.sibling_path_guard_diff.v1``::

    {
      "schema": "auditooor.sibling_path_guard_diff.v1",
      "pair": "deposit|withdraw",
      "pair_kind": "naming-convention" | "variant-arm",
      "shared_invariant_hint": "...",
      "path_a": {"name": "...", "file": "...", "line": N},
      "path_b": {"name": "...", "file": "...", "line": N},
      "guard_on_a_missing_on_b": ["onlyOwner", ...],
      "guard_on_b_missing_on_a": [...],
      "file_lines": ["file:line", "file:line"],
      "verdict": "asymmetry-candidate"
    }

Verdict vocabulary (``--check`` mode)
-------------------------------------
- ``pass-no-asymmetry``         no sibling pair has a guard asymmetry.
- ``found-asymmetries(N)``      N asymmetry rows were emitted.
- ``pass-no-source``            no in-scope .sol/.vy/.go/.rs/.move/.cairo source found.
- ``error``                     unreadable workspace / internal error.

This is the proactive FDG-vs-L2Oracle detector: it surfaces the asymmetric
in-tree guard at audit time instead of waiting for the operator to suspect
it. It emits CANDIDATES for human triage (same discipline as L30): each
row is a path to investigate, not a confirmed bug.

This pass does NOT write the R81 depth certificate. It only emits the per-row
``sibling_guard_asymmetries.jsonl`` above; the SINGLE cert writer is
``tools/depth-certificate-build.py``, which rolls these rows up into
``<ws>/.auditooor/depth_certificate.json``. The depth-certificate GATE
(``tools/depth-certificate-check.py``) then reads that cert.

CLI
---
    python3 tools/sibling-path-guard-diff.py --workspace <ws> [--check] [--json]

Exit code
---------
- 0 on ``pass-no-asymmetry`` / ``found-asymmetries`` / ``pass-no-source``.
- 2 on ``error`` (bad arguments / missing workspace).

Dependency-free: stdlib only, offline-safe, never executes target code.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = "auditooor.sibling_path_guard_diff.v1"
GATE = "SIBLING-PATH-GUARD-DIFF"

# --------------------------------------------------------------------------
# Shared scope-exclusion helper (single source of truth for OOS / test /
# vendored / generated). Path-loaded the same way as the sibling-tool loaders
# below (e.g. _resolve_src_roots), so it works whether or not tools/ is on
# sys.path. If unavailable we fall back to the legacy in-file heuristics so the
# tool never crashes - but the helper is the authoritative classifier.
# --------------------------------------------------------------------------
def _load_scope_exclusion():
    try:
        _p = Path(__file__).resolve().parent / "lib" / "scope_exclusion.py"
        _s = importlib.util.spec_from_file_location(
            "auditooor_scope_exclusion_spgd", _p)
        _m = importlib.util.module_from_spec(_s)
        _s.loader.exec_module(_m)
        return _m
    except Exception:  # pragma: no cover - keep the tool importable standalone
        return None


_SCOPE = _load_scope_exclusion()

# --------------------------------------------------------------------------
# L30 sibling pair list (canonical) + a few common extras. Each entry is an
# (arm_a_token, arm_b_token, shared_invariant_hint). Token matching is
# case-insensitive substring on the function/method NAME.
# --------------------------------------------------------------------------
_NAMING_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("deposit", "withdraw", "deposit and withdraw must apply symmetric balance/access guards"),
    ("mint", "burn", "mint and burn must apply symmetric supply/access guards"),
    ("claim", "finalize", "claim and finalize must apply symmetric leaf-status/state guards"),
    ("supply", "borrow", "supply and borrow must apply symmetric collateral/access guards"),
    ("propose", "execute", "propose and execute must apply symmetric authorization/timelock guards"),
    ("lock", "unlock", "lock and unlock must apply symmetric ownership/state guards"),
    ("escrow", "release", "escrow and release must apply symmetric custody guards"),
    ("vote", "tally", "vote and tally must apply symmetric eligibility/state guards"),
    ("sender", "receiver", "sender-side and receiver-side paths must apply symmetric validation guards"),
    # common extras
    ("stake", "unstake", "stake and unstake must apply symmetric balance/access guards"),
    ("freeze", "unfreeze", "freeze and unfreeze must apply symmetric authorization guards"),
    ("add", "remove", "add and remove must apply symmetric membership/access guards"),
    ("enable", "disable", "enable and disable must apply symmetric authorization guards"),
    ("open", "close", "open and close must apply symmetric state guards"),
    ("wrap", "unwrap", "wrap and unwrap must apply symmetric balance guards"),
)

# Cap the per-name-group pairwise comparison. The sibling-variant / naming-pair
# heuristics are O(group^2) per name. In Go (and any large fork) a common method
# name - String/Read/Write/Close/Len/Reset/new/init - recurs across thousands of
# files, so a single name-group can hold thousands of arms; one such group is
# millions of _diff_pair calls, and several explode virtual memory into the
# hundreds-of-GB range (observed: 396G VSZ on the bor fork, thrashing the host).
# A name shared by more than this many arms is interface boilerplate (Stringer,
# io.Reader, constructors), NOT a genuine FDG-vs-L2Oracle sibling-variant guard,
# so skipping those groups is a precision win as well as a perf bound. Tunable
# via AUDITOOOR_SIBLING_DIFF_MAX_GROUP (0/negative = unbounded). Generic.
_MAX_ARMS_PER_NAME_GROUP = int(
    os.environ.get("AUDITOOOR_SIBLING_DIFF_MAX_GROUP", "50") or "50"
)

# --------------------------------------------------------------------------
# Guard-call detection per language. Each entry is a compiled regex whose
# first non-empty captured group (or whole match) names the guard.
# Guards are normalized (lowercased, trimmed) before set diff.
# --------------------------------------------------------------------------
# Solidity: require/revert/assert + modifiers on the declaration line +
# common access/state guard idioms.
_SOL_GUARD_RES = [
    re.compile(r"\brequire\s*\(\s*([A-Za-z_][\w.]*)"),
    re.compile(r"\brevert\s+([A-Za-z_]\w*)"),
    re.compile(r"\bassert\s*\(\s*([A-Za-z_][\w.]*)"),
    re.compile(r"\b(only[A-Z]\w*)\b"),
    re.compile(r"\b(whenNotPaused|whenPaused|nonReentrant)\b"),
    re.compile(r"\b(_check[A-Z]\w*|_validate[A-Z]\w*|_require[A-Z]\w*)\b"),
    re.compile(r"\b(verify[A-Z]\w*|validate[A-Z]\w*)\s*\("),
]
# Rust: ensure!/assert!/require!/panic-class + verify_*/validate_*/check_*.
_RS_GUARD_RES = [
    re.compile(r"\b(ensure|require|assert|assert_eq|assert_ne)\s*!\s*\("),
    re.compile(r"\b(ensure_signed|ensure_root|ensure_none|ensure_origin)\b"),
    re.compile(r"\b((?:verify|validate|check)_\w+)\s*\("),
    re.compile(r"\.(ok_or|ok_or_else)\s*\("),
    re.compile(r"\b(require_keys_eq|require_keys_neq|require_gte|require_gt)\s*!"),
]
# Go: explicit if-err / return-err guard idioms + Validate*/Verify*/check*.
_GO_GUARD_RES = [
    re.compile(r"\b((?:Validate|Verify|Check|Require|Ensure|Assert)\w*)\s*\("),
    re.compile(r"\b(sdkerrors\.\w+|errors\.New)\s*\("),
    re.compile(r"\b(panic)\s*\("),
]
# Generic fallback for unknown extensions.
_GENERIC_GUARD_RES = [
    re.compile(r"\b((?:require|assert|ensure|verify|validate|check)\w*)\b", re.IGNORECASE),
    re.compile(r"\b(only[A-Z]\w*)\b"),
]

# Move: assert! macro, abort, acquires/has-capability, ensure-style helpers.
_MOVE_GUARD_RES = [
    re.compile(r"\b(assert!)\s*\("),
    re.compile(r"\b(abort)\b"),
    re.compile(r"\b(acquires)\b"),
    re.compile(r"\b((?:verify|validate|check|ensure|assert)_\w+)\s*\("),
]
# Cairo: assert / assert_* helpers, panic_with_felt252, ensure-style helpers.
_CAIRO_GUARD_RES = [
    re.compile(r"\b(assert)\s*\("),
    re.compile(r"\b(assert_\w+)\s*\("),
    re.compile(r"\b(panic_with_felt252|panic)\s*\("),
    re.compile(r"\b((?:verify|validate|check|ensure)_\w+)\s*\("),
]
# Vyper: assert / raise + verify_*/validate_*/check_* helper calls.
_VY_GUARD_RES = [
    re.compile(r"\b(assert)\b"),
    re.compile(r"\b(raise)\b"),
    re.compile(r"\b((?:verify|validate|check)_\w+)\s*\("),
]
_LANG_BY_EXT = {
    ".sol": "sol", ".rs": "rs", ".go": "go",
    ".move": "move", ".cairo": "cairo", ".vy": "vy",
}
_GUARD_RES_BY_LANG = {
    "sol": _SOL_GUARD_RES,
    "rs": _RS_GUARD_RES,
    "go": _GO_GUARD_RES,
    "move": _MOVE_GUARD_RES,
    "cairo": _CAIRO_GUARD_RES,
    "vy": _VY_GUARD_RES,
    "generic": _GENERIC_GUARD_RES,
}

# Function/method declaration extractors per language. Each yields
# (name, decl_line_index, body_start_line_index).
_SOL_FN_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")
_RS_FN_RE = re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]")
_GO_FN_RE = re.compile(r"\bfunc\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(")
# Move (.move): `fun name(` / `public fun name(` / `entry fun name(`.
_MOVE_FN_RE = re.compile(r"\bfun\s+([A-Za-z_]\w*)\s*[<(]")
# Cairo (.cairo): `fn name(` (Cairo 1.x mirrors Rust function syntax).
_CAIRO_FN_RE = re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]")
# Vyper (.vy): `def name(` (indent-bodied; body span is indent-aware below).
_VY_FN_RE = re.compile(r"\bdef\s+([A-Za-z_]\w*)\s*\(")

# Rust trait-impl context: `impl <Trait> for <Type>` (captures Trait, Type).
_RS_IMPL_RE = re.compile(
    r"\bimpl\s*(?:<[^>]*>\s*)?([A-Za-z_]\w*)\s+for\s+([A-Za-z_]\w*)"
)

# LEGACY fallback only. The OOS / test / vendored / generated exclusion is now
# owned by tools/lib/scope_exclusion.py (the single source of truth across all
# depth/coverage gates). These literals are consulted ONLY when that helper
# cannot be loaded, so the tool degrades gracefully instead of crashing.
_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "target", "dist", "build", "out",
    "lib", "cache", ".auditooor",
}
_TEST_HINTS = ("/test/", "/tests/", "_test.go", ".t.sol", "test_", "/mock", "/mocks/")
# Path SEGMENTS (not leading-slash substrings) marking a file as outside the
# in-scope implementation surface for sibling-guard diffing. LEGACY fallback for
# the test/mock/certora classes - the shared helper now owns these. (Generic.)
_NON_IMPL_SEGMENTS = (
    "interfaces", "interface", "certora", "test", "tests", "mock", "mocks",
)
# TOOL-SPECIFIC NON-scope filter (NOT owned by the shared helper, KEPT here):
# a Solidity interface declares body-less, guard-less signatures, so pairing an
# impl against its interface is a guaranteed FALSE asymmetry. The shared helper
# excludes an interfaces/ DIR, but a top-level I<Name>.sol file (PascalCase
# after the I) outside such a dir is an interface by NAME convention and is not
# the production guard surface either - so we keep this filter on top of is_oos.
_SOL_IFACE_NAME_RE = re.compile(r"^I[A-Z][A-Za-z0-9]*\.sol$")


def _is_sol_interface_name(rel: str) -> bool:
    """TOOL-SPECIFIC: top-level Solidity interface by I<Name>.sol filename
    convention (not a guard surface, not OOS in the generic sense)."""
    return bool(_SOL_IFACE_NAME_RE.match(Path(rel).name))


def _top_module(path: str) -> str:
    """Coarse module key for naming-convention siblings."""
    parts = Path(path).parts
    for anchor in ("modules", "pallets", "apps", "clients", "consensus"):
        if anchor in parts:
            i = parts.index(anchor)
            if i + 1 < len(parts):
                return "/".join(parts[i:i + 2])
    return "/".join(parts[:-1][-2:])


# Generic Solidity bases/interfaces that DO NOT make two contracts "siblings": every
# contract inherits some of these, so a shared generic base is not evidence of a
# shared logical role. Lowercased; matched against a contract's `is ...` list.
_GENERIC_SOL_BASES = {
    "context", "contextupgradeable", "ownable", "ownableupgradeable", "ownable2step",
    "ownable2stepupgradeable", "initializable", "reentrancyguard",
    "reentrancyguardupgradeable", "pausable", "pausableupgradeable", "accesscontrol",
    "accesscontrolupgradeable", "uupsupgradeable", "erc165", "erc165upgradeable",
    "erc20", "erc20upgradeable", "erc4626", "erc4626upgradeable", "erc721", "erc1155",
    "ierc20", "ierc20metadata", "ierc165", "ierc4626", "ierc721", "ierc1155",
    "multicall", "eip712", "eip712upgradeable", "nonces",
}


@dataclass
class FnArm:
    name: str
    file: str
    line: int  # 1-based decl line
    guards: set  # normalized guard tokens
    ctx_type: str = ""  # for Rust trait-impl arms: the impl Type
    ctx_trait: str = ""  # for Rust trait-impl arms: the impl Trait
    bases: frozenset = field(default_factory=frozenset)  # Solidity: declaring contract's bases/interfaces


@dataclass
class Asymmetry:
    pair: str
    pair_kind: str
    shared_invariant_hint: str
    arm_a: FnArm
    arm_b: FnArm
    a_missing_on_b: list
    b_missing_on_a: list

    def to_record(self) -> dict:
        gap_id = "ASYM-" + hashlib.sha1(
            f"{self.arm_a.file}:{self.arm_a.line}|{self.arm_b.file}:{self.arm_b.line}".encode()
        ).hexdigest()[:12]
        return {
            "schema": SCHEMA,
            "candidate_gap_id": gap_id,
            "pair": self.pair,
            "pair_kind": self.pair_kind,
            "shared_invariant_hint": self.shared_invariant_hint,
            "path_a": {"name": self.arm_a.name, "file": self.arm_a.file, "line": self.arm_a.line},
            "path_b": {"name": self.arm_b.name, "file": self.arm_b.file, "line": self.arm_b.line},
            "guard_on_a_missing_on_b": sorted(self.a_missing_on_b),
            "guard_on_b_missing_on_a": sorted(self.b_missing_on_a),
            "file_lines": [
                f"{self.arm_a.file}:{self.arm_a.line}",
                f"{self.arm_b.file}:{self.arm_b.line}",
            ],
            "verdict": "asymmetry-candidate",
        }


def _is_out_of_scope(rel: str, ws: Path | None = None) -> bool:
    """Should this file be excluded from the sibling-guard sweep?

    Delegates the OOS / test / vendored / generated decision to the shared
    helper (tools/lib/scope_exclusion.py) - the single source of truth. When a
    workspace + its in-scope manifest are available, the helper is
    MANIFEST-AUTHORITATIVE (is_in_scope trusts the curated denominator); else it
    fail-safes to ``not is_oos`` (more coverage, never less).

    The Solidity-interface-by-name filter (I<Name>.sol) is TOOL-SPECIFIC and not
    part of the generic OOS decision, so it is layered on top here and KEPT.

    FALLBACK: if the shared helper could not be loaded, fall back to the legacy
    in-file heuristics so the tool never crashes.
    """
    if _SCOPE is not None:
        # `rel` here is ws-relative (the caller passes a ws-relative path), so
        # manifest membership keys line up with the manifest's `file` field.
        if ws is not None:
            if not _SCOPE.is_in_scope(rel, workspace=ws):
                return True
        elif _SCOPE.is_oos(rel):
            return True
        # tool-specific interface-by-name filter (on top of the generic verdict)
        if _is_sol_interface_name(rel):
            return True
        return False
    # ---- legacy fallback (shared helper unavailable) ----
    low = rel.lower()
    if any(h in low for h in _TEST_HINTS):
        return True
    segs = [seg.lower() for seg in Path(rel).parts]
    if any(seg in _NON_IMPL_SEGMENTS for seg in segs):
        return True
    if _is_sol_interface_name(rel):
        return True
    return False


# Back-compat alias: the original test-path predicate name (some callers /
# tests may reference it). Routes through the shared-helper-backed classifier.
def _is_test_path(rel: str) -> bool:
    return _is_out_of_scope(rel, ws=None)


def _legacy_skip_dir(p: Path) -> bool:
    """LEGACY dir-prune, used only when the shared helper is unavailable. With
    the helper present, vendored/build/tooling dirs are dropped by is_oos on the
    per-file rel, so we only prune .git/.auditooor (non-source, never in-scope)
    to keep the walk cheap."""
    if _SCOPE is not None:
        return any(part in {".git", ".auditooor"} for part in p.parts)
    return any(part in _SKIP_DIRS for part in p.parts)


def _iter_source_files(root: Path, ws: Path | None = None):
    """Walk ``root`` for in-scope source. ``ws`` (when given) is the workspace
    root used to derive the ws-relative path for manifest-authoritative scope
    membership; the yielded ``rel`` stays root-relative for back-compat."""
    base = ws if ws is not None else root
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if _legacy_skip_dir(p):
            continue
        if p.suffix not in _LANG_BY_EXT:
            continue
        rel = str(p.relative_to(root))
        # ws-relative path for the scope decision (manifest keys are ws-relative);
        # fall back to root-relative if p is not under base.
        try:
            scope_rel = str(p.relative_to(base))
        except ValueError:
            scope_rel = rel
        if _is_out_of_scope(scope_rel, ws=ws):
            continue
        yield p, _LANG_BY_EXT[p.suffix], rel


# --------------------------------------------------------------------------
# Function-body extraction (brace-aware for sol/go/rs; the guard set is
# scoped to the arm body, not the whole file).
# --------------------------------------------------------------------------
def _extract_indent_span(lines: list, decl_idx: int) -> tuple:
    """Indent-aware body span for Vyper (.vy). The body is every line below the
    ``def`` more-indented than the def itself, ending at the first non-blank
    line whose indent is <= the def indent. Returns (body_start, body_end)
    inclusive; if no indented body follows, returns (decl_idx, decl_idx)."""
    n = len(lines)
    def_indent = len(lines[decl_idx]) - len(lines[decl_idx].lstrip())
    start = None
    end = decl_idx
    for i in range(decl_idx + 1, n):
        ln = lines[i]
        if not ln.strip():
            continue
        indent = len(ln) - len(ln.lstrip())
        if indent <= def_indent:
            break
        if start is None:
            start = i
        end = i
    if start is None:
        return decl_idx, decl_idx
    return start, end


def _extract_body_span(lines: list, decl_idx: int, lang: str = "") -> tuple:
    """Return (body_start_idx, body_end_idx) inclusive, brace-balanced from
    the first ``{`` at/after decl_idx. If no brace is found within a small
    window (e.g. an interface/abstract decl), returns (decl_idx, decl_idx).

    For indent-bodied languages (Vyper) there are no braces, so the span is
    the contiguous block of lines indented deeper than the ``def`` line, up to
    the next line at or below the declaration's indent (mirrors Python/Vyper
    block structure)."""
    if lang == "vy":
        return _extract_indent_span(lines, decl_idx)
    depth = 0
    started = False
    n = len(lines)
    # Find the opening brace (may be on a later line for multi-line sigs).
    open_idx = None
    for i in range(decl_idx, min(decl_idx + 12, n)):
        if "{" in lines[i]:
            open_idx = i
            break
    if open_idx is None:
        return decl_idx, decl_idx
    for i in range(open_idx, n):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        if started and depth <= 0:
            return open_idx, i
    return open_idx, n - 1


def _collect_guards(lines: list, start: int, end: int, decl_idx: int, lang: str) -> set:
    """Collect normalized guard tokens from the declaration line (for
    Solidity modifiers) plus the body span [start, end]."""
    guards: set = set()
    res = _GUARD_RES_BY_LANG.get(lang, _GENERIC_GUARD_RES)
    # Modifiers live on the decl line(s) before the body opening brace.
    scan_start = decl_idx
    for i in range(scan_start, min(end + 1, len(lines))):
        text = lines[i]
        for rx in res:
            for m in rx.finditer(text):
                tok = None
                for g in m.groups():
                    if g:
                        tok = g
                        break
                if tok is None:
                    tok = m.group(0)
                tok = tok.strip().lower()
                # Drop trivial/structural tokens.
                if not tok or tok in {"new", "panic", "errors.new"}:
                    # keep panic only if nothing else; treat as weak guard
                    if tok == "panic":
                        guards.add("panic")
                    continue
                guards.add(tok)
    return guards


def _extract_arms(path: Path, lang: str, rel: str) -> list:
    """Extract every function/method arm in the file with its guard set."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return []
    lines = text.splitlines()
    arms: list = []

    fn_re = {
        "sol": _SOL_FN_RE, "rs": _RS_FN_RE, "go": _GO_FN_RE,
        "move": _MOVE_FN_RE, "cairo": _CAIRO_FN_RE, "vy": _VY_FN_RE,
    }.get(lang)
    if fn_re is None:
        return arms

    # Pre-index Solidity contract-inheritance context by line so a function arm
    # knows its declaring contract's bases/interfaces (for the true-sibling gate).
    sol_ctx: dict = {}  # line_idx -> frozenset(base names)
    if lang == "sol":
        _con_re = re.compile(r"^\s*(?:abstract\s+)?contract\s+\w+\s+is\s+([^{]+?)\s*\{")
        cur = None  # (bases_frozenset, body_start, body_end)
        for i, ln in enumerate(lines):
            m = _con_re.search(ln)
            if m:
                s, e = _extract_body_span(lines, i, lang)
                bases = frozenset(
                    b.strip().split("(")[0].strip()
                    for b in m.group(1).split(",") if b.strip())
                cur = (bases, s, e)
            if cur and cur[1] <= i <= cur[2]:
                sol_ctx[i] = cur[0]

    # Pre-index Rust trait-impl context by line for variant-arm pairing.
    impl_ctx: dict = {}  # line_idx -> (trait, type)
    if lang == "rs":
        current = None  # (trait, type, impl_open_idx, impl_end_idx)
        for i, ln in enumerate(lines):
            m = _RS_IMPL_RE.search(ln)
            if m:
                s, e = _extract_body_span(lines, i)
                current = (m.group(1), m.group(2), s, e)
            if current and current[2] <= i <= current[3]:
                impl_ctx[i] = (current[0], current[1])

    for i, ln in enumerate(lines):
        m = fn_re.search(ln)
        if not m:
            continue
        name = m.group(1)
        start, end = _extract_body_span(lines, i, lang)
        # SOLIDITY view/pure skip (Strata 2026-07-07): a `view`/`pure` function
        # mutates no state and moves no funds, so it needs no reentrancy /
        # access-control / cap guard - any "guard asymmetry" against it is spurious
        # (18/25 depth gaps were maxDeposit/maxWithdraw view accessors). Exclude it
        # from guard-asymmetry pairing. Scan the signature span (decl line .. body
        # open) for a `view`/`pure` mutability token AFTER the param-list close, so a
        # param/var merely named 'view' does not trip it.
        if lang == "sol":
            _sig = " ".join(lines[i:max(i + 1, start + 1)])
            _pre = _sig.split("{", 1)[0]          # signature only, drop the body
            _pre = re.sub(r"\([^)]*\)", " ", _pre, count=1)  # drop the param list
            if re.search(r"\b(view|pure)\b", _pre):
                continue
        guards = _collect_guards(lines, start, end, i, lang)
        ctx_trait, ctx_type = "", ""
        if lang == "rs" and i in impl_ctx:
            ctx_trait, ctx_type = impl_ctx[i]
        arms.append(FnArm(
            name=name, file=rel, line=i + 1, guards=guards,
            ctx_type=ctx_type, ctx_trait=ctx_trait,
            bases=sol_ctx.get(i, frozenset()),
        ))
    return arms


# --------------------------------------------------------------------------
# Pairing
# --------------------------------------------------------------------------
def _name_matches_token(name: str, token: str) -> bool:
    return token.lower() in name.lower()


def _diff_pair(arm_a: FnArm, arm_b: FnArm, pair: str, kind: str, hint: str):
    """Return an Asymmetry if the two arms have a guard-set asymmetry, else None."""
    a_missing = sorted(arm_a.guards - arm_b.guards)
    b_missing = sorted(arm_b.guards - arm_a.guards)
    if not a_missing and not b_missing:
        return None
    # Require at least one side to have a guard the other lacks. Both empty
    # is symmetric (handled above). One side fully empty while the other has
    # guards is the canonical FDG-vs-L2Oracle shape.
    return Asymmetry(
        pair=pair, pair_kind=kind, shared_invariant_hint=hint,
        arm_a=arm_a, arm_b=arm_b,
        a_missing_on_b=a_missing, b_missing_on_a=b_missing,
    )


def _pair_naming_convention(arms: list) -> list:
    """Pair arms by the L30 naming-convention token list."""
    out: list = []
    seen_pairs: set = set()
    for tok_a, tok_b, hint in _NAMING_PAIRS:
        a_arms = [a for a in arms if _name_matches_token(a.name, tok_a)]
        b_arms = [a for a in arms if _name_matches_token(a.name, tok_b)]
        # Bound the a_arms x b_arms product: a token that matches thousands of
        # arms (boilerplate) would otherwise be millions of pairs / a VSZ blowup.
        if (
            _MAX_ARMS_PER_NAME_GROUP > 0
            and (len(a_arms) > _MAX_ARMS_PER_NAME_GROUP
                 or len(b_arms) > _MAX_ARMS_PER_NAME_GROUP)
        ):
            print(
                f"[sibling-path-guard-diff] skipping naming pair "
                f"'{tok_a}|{tok_b}': {len(a_arms)}x{len(b_arms)} arms exceeds "
                f"max-group {_MAX_ARMS_PER_NAME_GROUP} (boilerplate, not a "
                f"sibling-variant guard; set AUDITOOOR_SIBLING_DIFF_MAX_GROUP=0 "
                f"for unbounded)",
                file=sys.stderr,
            )
            continue
        for arm_a in a_arms:
            for arm_b in b_arms:
                if arm_a is arm_b or arm_a.name.lower() == arm_b.name.lower():
                    continue
                if arm_a.file != arm_b.file and _top_module(arm_a.file) != _top_module(arm_b.file):
                    # Coincidental names across unrelated modules are not L30
                    # sibling paths. The compact context extractor already
                    # filtered these later; doing it at source keeps the cert
                    # from inheriting noisy candidates.
                    continue
                key = tuple(sorted((
                    f"{arm_a.file}:{arm_a.line}", f"{arm_b.file}:{arm_b.line}"
                )))
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                asym = _diff_pair(arm_a, arm_b, f"{tok_a}|{tok_b}",
                                  "naming-convention", hint)
                if asym:
                    out.append(asym)
    return out


def _pair_variant_arms(arms: list) -> list:
    """Pair sibling implementations of the same logical handler:
    same method name, different file/type/trait-impl context. These are the
    FDG-vs-L2Oracle shape (two verifiers that should enforce the same
    defense)."""
    out: list = []
    seen_pairs: set = set()
    by_name: dict = {}
    for a in arms:
        by_name.setdefault(a.name.lower(), []).append(a)
    for name, group in by_name.items():
        if len(group) < 2:
            continue
        # A name shared by very many arms is interface boilerplate (String/Read/
        # Write/Close/new/init across thousands of Go files), not a sibling
        # variant of one logical handler. Pairing it is O(group^2) and blows up
        # memory (396G VSZ observed on bor); skip with a note for completeness.
        if _MAX_ARMS_PER_NAME_GROUP > 0 and len(group) > _MAX_ARMS_PER_NAME_GROUP:
            print(
                f"[sibling-path-guard-diff] skipping variant group "
                f"'{name}': {len(group)} arms exceeds max-group "
                f"{_MAX_ARMS_PER_NAME_GROUP} (interface boilerplate, not a "
                f"sibling-variant guard; set AUDITOOOR_SIBLING_DIFF_MAX_GROUP=0 "
                f"for unbounded)",
                file=sys.stderr,
            )
            continue
        # Only pair arms in DIFFERENT files or different Rust impl-types
        # (sibling variants), not two overloads in the same scope.
        for idx_a in range(len(group)):
            for idx_b in range(idx_a + 1, len(group)):
                arm_a, arm_b = group[idx_a], group[idx_b]
                if (
                    (arm_a.file.endswith(".rs") or arm_b.file.endswith(".rs"))
                    and (
                        not arm_a.ctx_trait
                        or not arm_b.ctx_trait
                        or arm_a.ctx_trait != arm_b.ctx_trait
                    )
                ):
                    # Rust inherent methods with the same name, such as
                    # unrelated `new` constructors, are not FDG-vs-L2Oracle
                    # sibling variants. Rust variant-arm pairing is only sound
                    # when both arms implement the same trait method.
                    continue
                same_file = arm_a.file == arm_b.file
                same_type = arm_a.ctx_type == arm_b.ctx_type and arm_a.ctx_type != ""
                if same_file and (same_type or not arm_a.ctx_type):
                    # same file, same/no impl-type -> overload, skip
                    continue
                # SOLIDITY true-sibling gate (Strata 2026-07-07): two same-named
                # Solidity functions are variant arms only if their declaring
                # contracts share a DOMAIN base/interface (mirrors the Rust
                # same-trait requirement above). Without it the pairer matched a
                # ubiquitous name like `balanceOf` across UNRELATED contracts (a
                # lens vs a cooldown), flooding the depth certificate with hundreds
                # of non-sibling gaps. FAIL-OPEN: if either contract has no parseable
                # domain base, keep the pair - never drop a real sibling (e.g. an
                # FDG-vs-L2Oracle shape, or a baseless standalone) on uncertainty.
                if arm_a.file.endswith(".sol") and arm_b.file.endswith(".sol"):
                    da = {b.lower() for b in arm_a.bases} - _GENERIC_SOL_BASES
                    db = {b.lower() for b in arm_b.bases} - _GENERIC_SOL_BASES
                    if da and db and not (da & db):
                        continue
                key = tuple(sorted((
                    f"{arm_a.file}:{arm_a.line}", f"{arm_b.file}:{arm_b.line}"
                )))
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                hint = (
                    f"variant arms of '{name}' must enforce the same defense "
                    f"(FDG-vs-L2Oracle shape)"
                )
                asym = _diff_pair(arm_a, arm_b, f"{name}~variant",
                                  "variant-arm", hint)
                if asym:
                    out.append(asym)
    return out


# --------------------------------------------------------------------------
# Workspace resolution
# --------------------------------------------------------------------------
def _resolve_src_roots(ws: Path) -> list:
    # Canonical source-root resolution: pick the DEEPEST candidate dir that
    # contains ALL the workspace source, so a Cargo workspace (crates/*) is not
    # mis-resolved to a thin src/src stub. See tools/lib/source_root_resolver.py.
    import importlib.util as _ilu
    _p = Path(__file__).resolve().parent / "lib" / "source_root_resolver.py"
    _s = _ilu.spec_from_file_location("auditooor_source_root_resolver", _p)
    _m = _ilu.module_from_spec(_s)
    _s.loader.exec_module(_m)
    return list(_m.resolve_src_roots(ws))

def evaluate(ws: Path) -> dict:
    if not ws.exists() or not ws.is_dir():
        return {"schema": SCHEMA, "gate": GATE, "verdict": "error",
                "reason": f"workspace not a directory: {ws}",
                "asymmetries": [], "count": 0}

    roots = _resolve_src_roots(ws)
    all_arms: list = []
    any_source = False
    for root in roots:
        for path, lang, _rel in _iter_source_files(root, ws=ws):
            any_source = True
            rel = str(path.relative_to(ws)) if _is_relative_to(path, ws) else str(path)
            arms = _extract_arms(path, lang, rel)
            all_arms.extend(arms)

    if not any_source:
        return {"schema": SCHEMA, "gate": GATE, "verdict": "pass-no-source",
                "reason": "no in-scope .sol/.vy/.go/.rs/.move/.cairo source found",
                "asymmetries": [], "count": 0}

    asyms: list = []
    asyms.extend(_pair_naming_convention(all_arms))
    asyms.extend(_pair_variant_arms(all_arms))

    records = [a.to_record() for a in asyms]
    count = len(records)
    verdict = f"found-asymmetries({count})" if count else "pass-no-asymmetry"
    return {
        "schema": SCHEMA, "gate": GATE, "verdict": verdict,
        "reason": (f"{count} sibling-path guard asymmetry candidate(s)"
                   if count else "no sibling-path guard asymmetry"),
        "asymmetries": records, "count": count,
    }


def _is_relative_to(p: Path, base: Path) -> bool:
    try:
        p.relative_to(base)
        return True
    except ValueError:
        return False


def _write_jsonl(ws: Path, records: list) -> Path:
    out_dir = ws / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "sibling_guard_asymmetries.jsonl"
    with out_path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return out_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Proactive sibling-path guard-asymmetry detector "
                    "(productionizes the L30 missing-guard enumerator).")
    ap.add_argument("--workspace", required=True, help="audit workspace path")
    ap.add_argument("--check", action="store_true",
                    help="emit verdict line (pass-no-asymmetry / found-asymmetries(N))")
    ap.add_argument("--json", action="store_true", help="emit full JSON result")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser()
    result = evaluate(ws)

    if result["verdict"] != "error":
        out_path = _write_jsonl(ws, result["asymmetries"])
        result["output_path"] = str(out_path)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"[{GATE}] verdict={result['verdict']} count={result['count']} "
              f"-- {result['reason']}")
        if args.check and result["asymmetries"]:
            for rec in result["asymmetries"]:
                fl = ", ".join(rec["file_lines"])
                print(f"  - {rec['pair']} ({rec['pair_kind']}): {fl}")

    if result["verdict"] == "error":
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
