#!/usr/bin/env python3
"""invariant-auto-synth.py - synthesize per-function invariant candidates from contract source.

r36-rebuttal: registered lane mimo-harness-build-2026-05-27.

Operator's "what should be true" gap. For each public/external function in a
Solidity / Rust pallet / Go module, this tool emits a short list of CANDIDATE
invariants the function SHOULD preserve. Invariants are derived from:

  1. Function signature (parameter types + return types -> shape-class)
  2. State writes (sstore / state.put / etc.) -> "preserved-balance" invariants
  3. Modifiers / require()s already present -> "the existing guard implies the
     invariant the dev had in mind" reverse-engineering
  4. Cross-function reads (this fn reads X that another fn writes) -> coupling
     invariants

Schema: auditooor.invariant_candidates.v1

USAGE:
  python3 tools/invariant-auto-synth.py --workspace ~/audits/<ws> \
    --src-glob 'src/**/*.sol' --output invariants.jsonl
"""
from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = "auditooor.invariant_candidates.v1"

REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# FIX-3 adversary-GOAL invariant axis (additive). The goal synthesizer routes a
# function through its matched impact_id(s) and emits GOAL-oriented relational
# templates bound against the source - the axis the shape-keyed synth_invariants_*
# functions below cannot phrase. Imported by path (tools/lib has no namespace
# package). Graceful: if the lib is missing, the goal column stays empty.
# ---------------------------------------------------------------------------
def _load_goal_synth():
    import importlib.util as _ilu

    tool = Path(__file__).resolve().parent / "lib" / "goal_invariant_synth.py"
    if not tool.is_file():
        return None
    try:
        spec = _ilu.spec_from_file_location("goal_invariant_synth", str(tool))
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


_GOAL_SYNTH = _load_goal_synth()


def _goal_invariants(function_name, function_signature, *, language, scope_text,
                     source_body, auth_sig_tail=""):
    """Thin wrapper: return (goal_records, bound_count). Empty/(0) when the goal
    lib is unavailable (additive, zero false credit)."""
    if _GOAL_SYNTH is None:
        return [], 0
    try:
        recs = _GOAL_SYNTH.goal_invariants_for(
            function_name, function_signature,
            language=language, scope_text=scope_text, source_body=source_body,
            auth_sig_tail=auth_sig_tail,
        )
    except Exception:  # noqa: BLE001
        return [], 0
    bound = sum(1 for r in recs if r.get("status") == "goal-bound")
    return recs, bound

# Real-incident invariant library. Each line is an invariant EXTRACTED from
# real audit findings (source_finding_ids), not synthesized from source-code
# shape. Before this wiring the tool read it ZERO times and emitted only
# regex-derived candidates; consuming it lets each synthesized function carry
# real-incident invariants for its language/category as grounding anchors.
INCIDENT_LIBRARY_PATH = (
    REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_pilot_audited.jsonl"
)

# Map a synthesized candidate string onto the incident-library `category`
# vocabulary so we can attach the matching real-incident invariants. Keys are
# substrings that appear in synth candidate slugs; values are library
# categories (see invariant_library_index.json per_category).
_CANDIDATE_CATEGORY_HINTS = (
    ("nonzero", "bounds"),
    ("amount", "bounds"),
    ("recipient", "authorization"),
    ("deadline", "freshness"),
    ("sum-", "conservation"),
    ("preserved", "conservation"),
    ("monoton", "monotonicity"),
    ("guard", "authorization"),
    ("role", "authorization"),
    ("auth", "authorization"),
    ("nonce", "uniqueness"),
    ("replay", "uniqueness"),
    ("reentr", "atomicity"),
)


def _lang_for_suffix(suffix: str) -> str:
    return {".sol": "solidity", ".rs": "rust", ".go": "go"}.get(suffix, "any")


def load_incident_library(
    path: Path = INCIDENT_LIBRARY_PATH,
) -> Dict[str, List[Dict[str, Any]]]:
    """Load the real-incident invariant library, indexed by language.

    Returns ``{lang: [record, ...]}`` where lang is one of
    ``solidity|rust|go|any``. A record retains ``invariant_id``,
    ``category``, ``statement``, ``source_count`` and ``source_finding_ids``
    so callers can attach grounded, traceable invariants. Returns ``{}`` when
    the library is absent (honest 0; the tool stays usable source-only).
    """
    by_lang: Dict[str, List[Dict[str, Any]]] = {}
    if not path.exists():
        return by_lang
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return by_lang
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or not rec.get("statement"):
            continue
        lang = (rec.get("target_lang") or "any").lower()
        entry = {
            "invariant_id": rec.get("invariant_id", ""),
            "category": (rec.get("category") or "").lower(),
            "statement": rec.get("statement", ""),
            "source_count": rec.get("source_count", 0),
            "source_finding_ids": rec.get("source_finding_ids", []),
            "verification_tier": rec.get("verification_tier", ""),
        }
        by_lang.setdefault(lang, []).append(entry)
    # Stable, highest-evidence-first ordering inside each language bucket.
    for lang in by_lang:
        by_lang[lang].sort(
            key=lambda e: (-int(e.get("source_count") or 0), e.get("invariant_id") or "")
        )
    return by_lang


def incident_invariants_for(
    candidates: List[str],
    lang: str,
    library: Dict[str, List[Dict[str, Any]]],
    limit: int = 3,
) -> List[Dict[str, Any]]:
    """Pick real-incident invariants matching this function's candidates.

    Matches on the inferred category vocabulary; falls back to the
    highest-evidence invariants for the language when no category hint fires
    but the function still wrote/guarded state (candidates present). Records
    are language-filtered (the function's language plus the ``any`` bucket).
    Returns [] when the library is empty.
    """
    if not candidates or not library:
        return []
    pool = list(library.get(lang, [])) + list(library.get("any", []))
    if not pool:
        return []
    cand_blob = " ".join(candidates).lower()
    wanted_cats = {cat for sub, cat in _CANDIDATE_CATEGORY_HINTS if sub in cand_blob}
    matched: List[Dict[str, Any]] = []
    seen: set = set()
    if wanted_cats:
        for entry in pool:
            if entry["category"] in wanted_cats and entry["invariant_id"] not in seen:
                matched.append(entry)
                seen.add(entry["invariant_id"])
                if len(matched) >= limit:
                    break
    if not matched:
        # No category hint matched: surface the top language-specific
        # real-incident invariants as generic grounding (still real, traceable).
        for entry in pool:
            if entry["invariant_id"] not in seen:
                matched.append(entry)
                seen.add(entry["invariant_id"])
                if len(matched) >= limit:
                    break
    return matched

# Solidity / EVM patterns
SOL_FN_RE = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)\s*"
    r"(?:(public|external|internal|private)\s+)?"
    r"(?:(view|pure|payable)\s+)?"
    r"(?:returns\s*\(([^)]*)\))?",
    re.MULTILINE | re.DOTALL,
)
SOL_REQUIRE_RE = re.compile(r"require\s*\(([^,;)]+)", re.MULTILINE)
SOL_STATE_WRITE_RE = re.compile(r"(\w+)\s*\[(\w+)\]\s*[+\-*/]?=")
SOL_MODIFIER_RE = re.compile(r"\bmodifier\s+(\w+)\s*\(")

# Scalar / struct state-write detector. The mapping-write regex above only sees
# `var[key] = ...`; a plain `pendingExitFeeChange = T({...})` / `acm = x` /
# `valuationKeeper = x` assignment is invisible to it, so a public/external
# setter that mutates a scalar or struct field produced ZERO candidates and the
# whole function got no invariant seed (Strata 2026-06-30: TwoStepConfigManager
# setters, the NAV-split + fee-change surface). Captures the assigned identifier
# at the START of an assignment (`name = expr`, not `==`/`>=`/`<=`/`!=`). Local
# `type name = ...` declarations are filtered separately in synth_invariants_sol.
SOL_SCALAR_WRITE_RE = re.compile(r"\b(\w+)\s*=\s*(?!=)")

# Solidity value-type leading tokens that mark a LOCAL variable declaration
# (`uint256 diff = ...`, `address to = ...`) rather than a state write. When a
# scalar-write match's preceding token is one of these (or `memory`/`storage`/
# `calldata` data-location keywords), it is a local decl, not a state mutation.
# Exact-match set:
_SOL_LOCAL_DECL_LEADERS = frozenset({
    "memory", "storage", "calldata", "bool", "address", "string", "var",
    "mapping",
})
# Numeric/byte value types carry a size suffix (`uint256`, `int128`, `bytes32`),
# so they are matched by PREFIX rather than exact identity.
_SOL_LOCAL_DECL_LEADER_PREFIXES = ("uint", "int", "bytes", "fixed", "ufixed")


def _sol_is_local_decl_leader(token: str) -> bool:
    """True if ``token`` is a Solidity value-type / data-location keyword that
    marks the assignment as a LOCAL variable declaration (`uint256 x = ...`),
    not a state write. Handles size-suffixed numeric/byte types by prefix."""
    if not token:
        return False
    if token in _SOL_LOCAL_DECL_LEADERS:
        return True
    return any(token.startswith(pfx) for pfx in _SOL_LOCAL_DECL_LEADER_PREFIXES)

# Value-math name keywords for internal/pure/view Solidity helpers. A helper
# whose name (or return shape) involves NAV split / 1-wei rounding / share-asset
# price math is exactly the ERC-4626 inflation / insolvency surface, but it has
# no state write and no amount/address param, so it produced ZERO candidates
# (Strata 2026-06-30: AccountingLib.splitValuatedNavOut,
# RoundingGuard.preferOriginalWithin1Wei, UD60x18Ext.max, ChainlinkAprProviderLib
# got no seed and 4 of the 8 unseeded files never recovered downstream).
_SOL_VALUE_MATH_KEYWORDS = (
    "nav", "split", "round", "wei", "max", "min", "apr", "fee", "share",
    "asset", "price", "valuat", "convert", "mul", "div",
)

# Rust patterns
RS_FN_RE = re.compile(
    r"(?:pub\s+)?fn\s+(\w+)\s*(?:<[^>]+>)?\s*\(([^)]*)\)"
    r"(?:\s*->\s*([^{]+))?",
    re.MULTILINE | re.DOTALL,
)
RS_ENSURE_RE = re.compile(r"ensure!\s*\(([^,;)]+)")
RS_REQUIRE_RE = re.compile(r"require_(?:root|signed|none)\s*\(")

# Go patterns
GO_FN_RE = re.compile(
    r"func\s+(?:\(\s*\w+\s+\*?\w+\s*\)\s+)?(\w+)\s*\(([^)]*)\)",
    re.MULTILINE,
)


# Solidity keywords that may legitimately sit between the `)` of the param list
# and the function body `{` WITHOUT being a custom modifier. Anything that is an
# identifier-shaped token NOT in this set (and not a `keyword(...)` call like
# `returns(...)`) is treated as a modifier application on THIS function.
_SOL_NON_MODIFIER_SIG_KEYWORDS = frozenset({
    "public", "external", "internal", "private",
    "view", "pure", "payable", "nonpayable",
    "virtual", "override", "returns",
})

# A bare identifier token (a modifier application is e.g. `onlyOwner` or
# `nonReentrant` or `onlyRole(ADMIN)` - we only need the leading identifier).
_SOL_IDENT_RE = re.compile(r"[A-Za-z_]\w*")

# `returns (...)` / `override (...)` carry type-name / base-contract identifiers
# inside their parenthesised arg list that are NOT modifiers. Strip those clauses
# before scanning so a `returns (uint256)` does not masquerade as a modifier.
_SOL_KEYWORD_ARGLIST_RE = re.compile(
    r"\b(?:returns|override)\s*\([^)]*\)", re.IGNORECASE)


def _sol_fn_has_modifier(sig_tail: str) -> bool:
    """Return True if THIS function's signature carries a modifier token.

    ``sig_tail`` is the source text between the end of the SOL_FN_RE match (which
    consumes visibility + mutability + an optional ``returns(...)``) and the
    opening ``{`` of the body. A custom-modifier application surfaces here as a
    bare identifier (``onlyOwner``, ``nonReentrant``, ``onlyRole``, ...) that is
    NOT one of the reserved signature keywords. This is a PER-FUNCTION check and
    replaces the prior file-level "any modifier declared anywhere" heuristic
    (which over-fired access-control-missing on every fn in a file that merely
    inherited its modifiers from a parent contract).
    """
    if not sig_tail:
        return False
    # Strip `returns(...)` / `override(...)` arg lists: the identifiers inside
    # them (return types, base-contract names) are NOT modifier applications. The
    # bare `override` / `returns` keyword that remains is in the reserved set.
    cleaned = _SOL_KEYWORD_ARGLIST_RE.sub(" ", sig_tail)
    # A custom modifier with an arg list (`onlyRole(ADMIN)`) still surfaces its
    # leading identifier; we only need that. Scan identifiers left-to-right and
    # ignore the reserved-keyword set.
    for ident in _SOL_IDENT_RE.findall(cleaned):
        if ident.lower() not in _SOL_NON_MODIFIER_SIG_KEYWORDS:
            return True
    return False


def synth_invariants_sol(fn_name: str, params: str, visibility: str,
                          fn_has_modifier: bool, body: str,
                          returns: str = "", mutability: str = "") -> list[str]:
    """Emit candidate invariants for a single Solidity function.

    ``fn_has_modifier`` is a PER-FUNCTION signal (does THIS function's signature
    apply a modifier), not a file-level "any modifier declared" flag.
    ``returns`` (optional, backward-compatible default "") is the return-type
    clause, used to detect value-math helpers by their return shape.
    ``mutability`` (optional, default "") is view/pure/payable - used so an
    assignment to a NAMED RETURN variable inside a pure/view helper is not
    mistaken for a state write.
    """
    cands = []
    p_lower = params.lower() if params else ""

    # Param-type-based invariants
    if "uint" in p_lower and "amount" in p_lower:
        cands.append(f"INV-{fn_name}-amount-nonzero: amount > 0")
    if "address" in p_lower and ("to" in p_lower or "recipient" in p_lower):
        cands.append(f"INV-{fn_name}-recipient-nonzero: recipient != address(0)")
    if "uint" in p_lower and "deadline" in p_lower:
        cands.append(f"INV-{fn_name}-deadline-future: deadline >= block.timestamp")

    # State-write-based invariants (mapping writes: var[key] = ...)
    writes = SOL_STATE_WRITE_RE.findall(body or "")
    for var, key in writes[:3]:
        cands.append(
            f"INV-{fn_name}-sum-{var}: sum_over_keys({var}) preserved or "
            "monotonically increases (depending on op)"
        )

    # Scalar / struct state-write invariant (additive). The mapping-write regex
    # above misses plain `pendingExitFeeChange = T({...})` / `acm = x` setters,
    # so a public/external function that mutates a scalar or struct field got NO
    # invariant seed at all. Detect a real scalar/struct state write (an
    # assignment whose target is NOT a local `type name =` declaration) and emit
    # a state-write-consistency candidate for public/external functions
    # regardless of param shape.
    body_text = body or ""
    mut_lower = (mutability or "").lower()
    # A pure/view function cannot write contract state by definition, so any
    # assignment in its body is to a local or named-return variable, never a
    # state mutation. Skip scalar-write detection for those.
    has_scalar_write = False
    if mut_lower in ("pure", "view"):
        body_text_for_writes = ""
    else:
        body_text_for_writes = body_text
    for sm in SOL_SCALAR_WRITE_RE.finditer(body_text_for_writes):
        # Token immediately preceding the assigned identifier; a local decl looks
        # like `<type> <name> =` so the preceding token is a type / data-location
        # keyword. A state write has a non-decl leader (statement start, `;`, `}`,
        # `)`, or `self.`-style member access).
        pre = body_text[max(0, sm.start() - 40):sm.start()]
        prev_tokens = _SOL_IDENT_RE.findall(pre)
        prev = prev_tokens[-1].lower() if prev_tokens else ""
        if _sol_is_local_decl_leader(prev):
            continue
        has_scalar_write = True
        break
    if has_scalar_write and visibility in ("public", "external"):
        cands.append(
            f"INV-{fn_name}-state-write-consistency: scalar/struct state write "
            "preserves the config/accounting invariants (two-step pending vs "
            "applied value, authorized actor, bounds) the setter is meant to hold"
        )

    # Precision / rounding invariant for internal/pure/view value-math helpers
    # (additive). These have no state write and no amount/address param, so they
    # produced zero candidates - yet NAV-split and 1-wei-rounding helpers are the
    # exact ERC-4626 inflation/insolvency surface. Fire when the function is
    # non-mutating (pure/view OR internal/private with no state write detected)
    # and its name or returns involve value math.
    n_lower = (fn_name or "").lower()
    ret_lower = (returns or "").lower()
    name_or_ret = n_lower + " " + ret_lower
    is_value_math = any(k in name_or_ret for k in _SOL_VALUE_MATH_KEYWORDS)
    # Non-mutating = explicitly pure/view, OR an internal/private helper with no
    # detected state write. (The precision/rounding axis targets pure math
    # helpers, which is where ERC-4626 inflation/insolvency bugs live.)
    non_mutating = mut_lower in ("pure", "view") or (
        not has_scalar_write and not writes
        and visibility in ("internal", "private")
    )
    if is_value_math and non_mutating:
        cands.append(
            f"INV-{fn_name}-precision-rounding: value-math helper rounds in the "
            "protocol's favor (no inflation / insolvency), is monotonic in its "
            "inputs, and the split of NAV/shares/assets conserves the total - no "
            "1-wei drift that lets a depositor extract value from the vault"
        )

    # Modifier-presence invariants. Gate on a PER-FUNCTION modifier-application
    # check (does THIS fn's signature carry a modifier token) rather than the
    # file-level "any modifier declared anywhere in the file" heuristic that
    # over-fired on every public/external fn whenever the contract inherited its
    # modifiers (e.g. onlyOwner from Ownable) instead of declaring them locally.
    if visibility in ("public", "external"):
        if not fn_has_modifier:
            cands.append(
                f"INV-{fn_name}-access-control-missing: public/external "
                "fn has NO modifier; verify access-control by-design or absent"
            )

    # Reentrancy invariant heuristic
    if ".call(" in body or ".transfer(" in body or ".send(" in body:
        cands.append(
            f"INV-{fn_name}-reentrancy: external call present; "
            "state writes must occur BEFORE external call (CEI pattern)"
        )

    return cands


def synth_invariants_rs(fn_name: str, params: str) -> list[str]:
    """Emit candidate invariants for a Rust (Substrate pallet) function."""
    cands = []
    p_lower = params.lower() if params else ""

    if "origin" in p_lower:
        cands.append(
            f"INV-{fn_name}-origin-checked: extrinsic must call "
            "ensure_signed/ensure_root/ensure_none on Origin"
        )
    if "amount" in p_lower or "value" in p_lower:
        cands.append(f"INV-{fn_name}-amount-nonzero: amount > Zero::zero()")
    if "weight" in p_lower:
        cands.append(
            f"INV-{fn_name}-weight-bounded: declared weight >= actual "
            "computation cost"
        )

    return cands


# Value-moving / accounting / economic-math name keywords for Go keeper functions.
# The (ctx,msg)-only gate below covered ONLY gRPC message handlers (msg_server.go) and
# missed the entire internal economic core - NAV/valuation, interest accrual, payout,
# reconcile, share/asset math (NUVA 2026-06-30: valuation_engine.go / abci.go / payout.go
# / reconcile.go got 0 hunt questions; BOTH filed findings live on exactly that surface).
_GO_VALUE_KEYWORDS = (
    "value", "valuation", "nav", "price", "share", "asset", "interest", "accrue",
    "payout", "reconcile", "mint", "burn", "deposit", "withdraw", "swap", "redeem",
    "balance", "supply", "rate", "compute", "calculate", "convert", "exchange",
    "principal", "fee", "reward", "collateral", "total", "settle", "distribute",
)
# Read-only name prefixes: a ctx-keeper method whose name starts with one of these is a
# getter/iterator (no state write) - excluded from the generic state-mutator catch-all to
# avoid flooding the hunt with view functions (the ranker would deprioritize them anyway).
_GO_READONLY_PREFIXES = ("get", "has", "is", "iterate", "list", "query", "load",
                         "read", "fetch", "lookup", "all", "find")


def synth_invariants_go(fn_name: str, params: str) -> list[str]:
    """Emit candidate invariants for a Go (Cosmos SDK keeper) function.

    Covers THREE shapes (was: only the gRPC (ctx,msg) handler shape):
      1. gRPC message handlers (ctx + msg)            -> ctx/msg validation
      2. value/accounting/economic-math keeper fns    -> conservation + no-overflow
      3. any remaining ctx state-mutator (non-getter) -> generic state-write guard
    Shapes 2/3 are what surface the internal economic core (NAV/interest/payout) that the
    handler-only gate left entirely unhunted."""
    cands: list[str] = []
    p_lower = params.lower() if params else ""
    n_lower = (fn_name or "").lower()

    if "ctx" in p_lower and ("msg" in p_lower or "sdk.msg" in p_lower):
        cands.append(
            f"INV-{fn_name}-ctx-validation: ctx.BlockHeight() check + "
            "msg.ValidateBasic() must pass before state write"
        )
    if "sender" in p_lower or "creator" in p_lower:
        cands.append(
            f"INV-{fn_name}-authz: sender authorized to perform op "
            "(check ownership / module account)"
        )

    # Shape 2: value-moving / accounting / economic-math keeper functions.
    if any(k in n_lower for k in _GO_VALUE_KEYWORDS):
        cands.append(
            f"INV-{fn_name}-accounting-conservation: total assets/shares conserved "
            "across this op - no unbacked mint, no value created or destroyed except by "
            "an intended deposit/withdraw/interest/payout"
        )
        cands.append(
            f"INV-{fn_name}-no-overflow-precision: NAV/interest/share arithmetic must "
            "not overflow, divide-by-zero, or lose precision in a way that lets value be "
            "extracted (principal theft) or wedges the state machine (permanent freeze)"
        )

    # Shape 3: any other ctx state-mutator (not a getter/iterator) still gets a generic
    # guard so it reaches a terminal verdict instead of being silently unhunted.
    if not cands and "ctx" in p_lower and not n_lower.startswith(_GO_READONLY_PREFIXES):
        cands.append(
            f"INV-{fn_name}-state-write-guard: every state write is authority/"
            "precondition-guarded and preserves the module's accounting invariants"
        )

    return cands


def process_sol_file(path: Path, library: Optional[Dict[str, Any]] = None) -> list[dict]:
    """Walk one Solidity file; emit per-fn invariant candidates."""
    library = library or {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    out = []
    for m in SOL_FN_RE.finditer(text):
        fn_name, params, visibility, mutability, returns = m.groups()
        # Body extraction (best-effort: find matching `{` after fn declaration)
        start = m.end()
        # Try to find a balanced { ... }
        depth = 0
        body_start = text.find("{", start)
        body_end = body_start
        if body_start >= 0:
            for i in range(body_start, min(body_start + 10000, len(text))):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        body_end = i
                        break
        body = text[body_start:body_end + 1] if body_start >= 0 else ""
        # PER-FUNCTION modifier check: any modifier application lands in the
        # signature tail between the regex match end and the body `{`.
        sig_tail = text[start:body_start] if body_start >= 0 else text[start:start]
        fn_has_modifier = _sol_fn_has_modifier(sig_tail)
        cands = synth_invariants_sol(fn_name, params or "", visibility or "",
                                      fn_has_modifier, body, returns or "",
                                      mutability or "")
        if cands:
            # FIX-3: additive adversary-GOAL axis. Resolve the function's matched
            # impact_id(s) and emit bound goal-invariant relations. NEVER clobbers
            # invariant_candidates - goal invariants are a separate column.
            goals, goal_bound = _goal_invariants(
                fn_name, params or "", language="solidity",
                scope_text=str(path), source_body=body,
                # sig_tail is the source between the regex match end and the body
                # `{` - it carries any applied modifier (onlyOwner / onlyRole),
                # the correct input for the caller_auth_guard role.
                auth_sig_tail=sig_tail)
            out.append({
                "schema_version": SCHEMA,
                "language": "solidity",
                "file": str(path),
                "function": fn_name,
                "visibility": visibility or "internal",
                "mutability": mutability or "nonpayable",
                "invariant_candidates": cands,
                "incident_invariants": incident_invariants_for(
                    cands, "solidity", library),
                "goal_invariants": goals,
                "goal_invariant_count_bound": goal_bound,
            })
    return out


def process_rs_file(path: Path, library: Optional[Dict[str, Any]] = None) -> list[dict]:
    library = library or {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    out = []
    for m in RS_FN_RE.finditer(text):
        fn_name, params, _ret = m.groups()
        cands = synth_invariants_rs(fn_name, params or "")
        if cands:
            goals, goal_bound = _goal_invariants(
                fn_name, params or "", language="rust",
                scope_text=str(path), source_body="")
            out.append({
                "schema_version": SCHEMA,
                "language": "rust",
                "file": str(path),
                "function": fn_name,
                "invariant_candidates": cands,
                "incident_invariants": incident_invariants_for(
                    cands, "rust", library),
                "goal_invariants": goals,
                "goal_invariant_count_bound": goal_bound,
            })
    return out


def process_go_file(path: Path, library: Optional[Dict[str, Any]] = None) -> list[dict]:
    library = library or {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    out = []
    for m in GO_FN_RE.finditer(text):
        fn_name, params = m.groups()
        cands = synth_invariants_go(fn_name, params or "")
        if cands:
            goals, goal_bound = _goal_invariants(
                fn_name, params or "", language="go",
                scope_text=str(path), source_body="")
            out.append({
                "schema_version": SCHEMA,
                "language": "go",
                "file": str(path),
                "function": fn_name,
                "invariant_candidates": cands,
                "incident_invariants": incident_invariants_for(
                    cands, "go", library),
                "goal_invariants": goals,
                "goal_invariant_count_bound": goal_bound,
            })
    return out


def _inscope_files(ws: Path) -> set:
    """Absolute paths of the in-scope source files from the authoritative manifest
    .auditooor/inscope_units.jsonl. Empty set when the manifest is absent (no
    enumerated scope -> caller keeps whole-tree behaviour).

    invariant-auto-synth SEEDS the entire impact-methodology per-function hunt, so an
    unscoped ws.rglob floods step-3 with OZ-lib / test / foreign-corpus functions and
    DROWNS the real in-scope units under the max-files cap (Strata 2026-06-30: 17
    in-scope files, but the synth scanned 200 OZ/ERC/lib/test files and the hunt
    referenced foreign functions like rawToConvertedEIPTx1559s). This is the SAME
    scope-allowlist discipline already applied to the inscope_units emitter,
    _source_file_records, and scope-md-parser - invariant-auto-synth was the 4th,
    most-damaging unscoped source-enumeration path."""
    mf = ws / ".auditooor" / "inscope_units.jsonl"
    out = set()
    if not mf.is_file():
        return out
    for line in mf.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        f = str(rec.get("file") or rec.get("path") or rec.get("source") or "")
        if not f:
            continue
        p = Path(f) if f.startswith("/") else (ws / f)
        try:
            out.add(str(p.resolve()))
        except OSError:
            out.add(str(p))
    return out


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--workspace", required=True)
    p.add_argument("--src-glob", default=None,
                   help="Override glob pattern (default: auto by ext)")
    p.add_argument("--output", required=True)
    p.add_argument("--max-files", type=int, default=200)
    p.add_argument("--incident-library", default=str(INCIDENT_LIBRARY_PATH),
                   help="Path to the real-incident invariant library JSONL "
                        "(default: %(default)s). Empty string disables.")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        sys.stderr.write(f"[invariant-synth] no workspace: {ws}\n")
        return 2

    records = []
    if args.src_glob:
        files = list(ws.glob(args.src_glob))
    else:
        files = (list(ws.rglob("*.sol")) + list(ws.rglob("*.rs"))
                  + list(ws.rglob("*.go")))
    # Exclude vendored / test / build dirs AND Solidity test/script suffixes.
    # .t.sol (Foundry test contracts) and .s.sol (Foundry deploy scripts) must
    # be excluded regardless of which directory they live in, because they may
    # appear outside the canonical test/ and script/ directories (e.g. src/).
    # r36-rebuttal: bugfix-inventory-claude-20260610
    _SKIP_DIRS = frozenset([
        "/node_modules/", "/.git/", "/test/", "/tests/", "/target/",
        "/lib/", "/dependencies/", "/forge-std/",
        "/build/", "/cache/", "/out/", "/artifacts/", "/script/",
        # Cosmos-SDK / test-harness dirs: simulation modules + the SimApp wiring +
        # test utilities + mock fakes are NOT auditable production surface (SCOPE:
        # "test/config files OOS"). The /test/ filter misses these because they are
        # non-_test.go files under conventionally-named harness dirs (NUVA 2026-06-30:
        # 134/844 ranked questions hit src/vault/simulation + simapp = wasted hunt).
        "/simulation/", "/simapp/", "/testutil/", "/testutils/",
        "/mocks/", "/mock/", "/fixtures/", "/e2e/",
    ])
    _SKIP_SOL_SUFFIXES = (".t.sol", ".s.sol")
    # Generated Go files (protobuf / gRPC-gateway / pulsar ORM) are machine-emitted
    # boilerplate, never an auditable surface - exclude so the broadened go invariant
    # synth does not flood the hunt with thousands of generated-stub questions
    # (NUVA 2026-06-30: events.pulsar.go alone produced 416).
    _SKIP_GO_SUFFIXES = (
        "_test.go", ".pb.go", ".pb.gw.go", ".pulsar.go", ".cosmos_orm.go",
        ".cosmos_proto.go", "_gen.go", ".gen.go", "mock_", "_mock.go",
    )
    files = [
        f for f in files
        if not any(skip in str(f) for skip in _SKIP_DIRS)
        and not (
            f.suffix == ".sol"
            and any(f.name.endswith(s) for s in _SKIP_SOL_SUFFIXES)
        )
        and not (
            f.suffix == ".go"
            and (any(f.name.endswith(s) for s in _SKIP_GO_SUFFIXES)
                 or f.name.startswith("mock_"))
        )
    ]
    # Scope-allowlist: when the workspace declares an enumerated in-scope manifest,
    # restrict to it BEFORE the max-files cap so the real in-scope units are not
    # drowned by vendored/library files the cap would otherwise keep. No manifest ->
    # keep the whole-tree behaviour (fresh ws / non-enumerated scope).
    _inscope = _inscope_files(ws)
    if _inscope:
        _scoped = [f for f in files if str(getattr(f, "resolve", lambda: f)()) in _inscope]
        if _scoped:
            sys.stderr.write(
                f"[invariant-synth] scope-allowlist: {len(_scoped)}/{len(files)} files "
                f"are in .auditooor/inscope_units.jsonl; restricting (was unscoped -> "
                f"hunt-seed scope-bleed)\n")
            files = _scoped
    files = files[:args.max_files]

    # Load the real-incident invariant library once and thread it through so
    # every synthesized function carries grounded, traceable real-incident
    # invariants (previously read ZERO times). Empty path / missing file ->
    # graceful source-only behaviour.
    library: Dict[str, Any] = {}
    if args.incident_library:
        library = load_incident_library(Path(args.incident_library))
        lib_total = sum(len(v) for v in library.values())
        sys.stderr.write(
            f"[invariant-synth] incident library: {lib_total} invariants "
            f"across {len(library)} language buckets "
            f"({args.incident_library})\n"
        )

    for f in files:
        if f.suffix == ".sol":
            records.extend(process_sol_file(f, library))
        elif f.suffix == ".rs":
            records.extend(process_rs_file(f, library))
        elif f.suffix == ".go":
            records.extend(process_go_file(f, library))

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    sys.stderr.write(f"[invariant-synth] wrote {len(records)} records over "
                     f"{len(files)} files to {out_path}\n")

    incident_attached = sum(len(r.get("incident_invariants", [])) for r in records)
    if args.json:
        print(json.dumps({"files": len(files), "records": len(records),
                          "incident_invariants_attached": incident_attached,
                          "incident_library_size": sum(len(v) for v in library.values()),
                          "out": str(out_path)}, indent=2))
    else:
        total_cands = sum(len(r["invariant_candidates"]) for r in records)
        print(f"files scanned: {len(files)} | functions with candidates: "
              f"{len(records)} | total invariant candidates: {total_cands} | "
              f"real-incident invariants attached: {incident_attached}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
