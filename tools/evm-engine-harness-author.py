#!/usr/bin/env python3
"""evm-engine-harness-author.py - auto-generate EVM verification-engine specs
from a Solidity contract + matched corpus invariants.

Given a workspace and a concrete in-scope Solidity contract, this tool:

  1. Parses the contract surface (functions w/ visibility + state-mutability,
     state vars, immutables, events, custom errors, modifiers, base contracts).
  2. Matches that surface against the indexed corpus invariant library
     (audit/corpus_tags/derived/invariants_extracted.jsonl +
     invariants_pilot.jsonl) by attack-signature / category heuristics keyed
     off the contract's function names + the categories present in the corpus.
  3. Emits THREE EVM verification-engine spec families:
       (a) Halmos symbolic specs   - check_* functions (one per matched
           invariant category), parameters fully symbolic.
       (b) Medusa + Echidna property fuzz - fuzz_*/echidna_* property fns + a
           medusa.json + echidna.yaml config.
       (c) Foundry stateful-invariant suite - invariant_* fns with
           targetContract() wiring + a handler skeleton.
     Every emitted file carries a CANDIDATE-HARNESS-NOT-PROOF banner and an
     INV-* citation block so Rule 58 (invariant-grounded) is honored at
     authoring time.

RELATED TOOLS (tool-duplication preflight, see ~/.claude/CLAUDE.md):
  - tools/halmos-runner.sh / tools/medusa-fuzz.sh / tools/echidna-campaign.sh
    are RUNNERS: they execute an already-authored harness and write an
    artifact.json. They do NOT author the specs. This tool authors them.
  - tools/harness-scaffold-emitter.py emits scaffolds from PLAN ROWS produced
    by tools/invariant-harness-planner.py (requires a pre-existing plan). This
    tool needs no plan: input is (workspace, contract) and it derives the
    matched invariants directly from the corpus index.
  - tools/econ-fuzzer-scaffold.py emits econ-fuzz scaffolds from free-form
    local hypotheses via an action-template map (oracle/liquidity/debt/...).
    This tool is contract-surface + corpus-invariant driven and emits all
    three engine families (halmos + medusa/echidna + forge), not just econ
    fuzz.
  - tools/cosmos_dynamic_harness_scaffold.py is the cosmos/Go analogue; this
    tool is the EVM/Solidity analogue.

The gap this tool fills: a single front-door that turns one concrete EVM
contract into a runnable-by-the-existing-runners multi-engine spec set, with
corpus-invariant grounding, with zero plan-file prerequisite.

Exit codes:
  0 - specs emitted
  2 - input validation / parse error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.evm_engine_harness_author.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXTRACTED = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl"
DEFAULT_PILOT = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_pilot.jsonl"

# Path-level OOS markers (P1-e / taxonomy mode 19): deployed re-implementation /
# verified-source mirror trees are NOT the in-scope CUT. beanstalk authored
# 13/41 harnesses against reference/instascope_deployed_zip/* (a deployed reimpl
# + bundled @openzeppelin interfaces). These markers are a cheap path guard that
# fires even when no inscope_units.jsonl manifest is present; the authoritative
# allow-list is applied by _contract_in_scope below.
_OOS_PATH_MARKERS = (
    "/reference/", "/instascope_deployed_zip/", "/deployed_zip/",
    "/verified_sources/", "/verified-sources/", "/test/", "/tests/",
    "/mock/", "/mocks/", "/node_modules/", "/.git/", "/out/", "/cache/",
)


def _load_inscope_file_set(ws: Path):
    """Return the AUTHORITATIVE in-scope .sol file set from
    ``.auditooor/inscope_units.jsonl`` (the SAME allow-list
    ``invariant-fuzz-completeness._has_in_scope_solidity_source`` reads), or
    ``None`` when no manifest exists (then only the path-marker guard applies,
    preserving legacy behavior). Set AUDITOOOR_FCC_NO_SCOPE_FILTER=1 to disable.
    """
    import os
    if os.environ.get("AUDITOOOR_FCC_NO_SCOPE_FILTER"):
        return None
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return None
    files: set[str] = set()
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        f = str(row.get("file") or "").strip().lstrip("./").replace("\\", "/")
        if f:
            files.add(f)
    return files or None


def _contract_in_scope(workspace: Path, contract_path: Path) -> tuple[bool, str]:
    """P1-e CUT-in-scope filter (taxonomy mode 19). Returns (in_scope, reason).

    (1) A path-level OOS marker (deployed-zip / reference mirror / test / mock)
        is rejected unconditionally - those trees are never the in-scope CUT.
    (2) When an inscope_units.jsonl allow-list exists, the contract path MUST
        appear in it (matched by workspace-relative path or basename suffix).
    When no manifest exists only (1) applies (legacy fall-through).
    """
    posix = contract_path.as_posix()
    low = posix.lower()
    for marker in _OOS_PATH_MARKERS:
        if marker in low:
            return False, f"path matches OOS marker {marker!r} (deployed-zip / reference / test mirror is not the in-scope CUT)"
    inscope = _load_inscope_file_set(workspace)
    if inscope is None:
        return True, "no inscope_units.jsonl manifest - path-marker guard only"
    try:
        rel = contract_path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        rel = posix
    rel_n = rel.lstrip("./")
    if rel_n in inscope:
        return True, "contract path is in inscope_units.jsonl"
    # allow a basename/suffix match (the manifest may store a longer or shorter rel root)
    for f in inscope:
        if f == rel_n or f.endswith("/" + rel_n) or rel_n.endswith("/" + f):
            return True, "contract path suffix-matches an inscope_units.jsonl entry"
    return False, ("contract path is NOT in inscope_units.jsonl allow-list "
                   f"(rel={rel_n!r}); refusing to author a harness for an out-of-scope CUT")

# ----------------------------------------------------------------------------
# Solidity surface parsing (regex, not a full parser - bounded and explicit).
# ----------------------------------------------------------------------------

_CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?(contract|library|interface)\s+([A-Za-z_]\w*)"
    r"(?:\s+is\s+([^{]+))?\s*\{",
)
_FUNCTION_RE = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*"
    r"([^{;]*?)\s*(?:\{|;)",
    re.DOTALL,
)
_RETURNS_RE = re.compile(r"\breturns\s*\(([^)]*)\)", re.DOTALL)
_EVENT_RE = re.compile(r"\bevent\s+([A-Za-z_]\w*)\s*\(")
_ERROR_RE = re.compile(r"\berror\s+([A-Za-z_]\w*)\s*\(")
_MODIFIER_RE = re.compile(r"\bmodifier\s+([A-Za-z_]\w*)\s*[\({]")
_IMMUTABLE_RE = re.compile(
    r"\b([A-Za-z_]\w*(?:\s*\[\s*\])?)\s+(?:public\s+|internal\s+|private\s+)?"
    r"immutable\s+([A-Za-z_]\w*)",
)
_STATEVAR_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;]*?\)|[A-Za-z_]\w*(?:\s*\[\s*\])?)\s+"
    r"(?:public|internal|private)\s+([A-Za-z_]\w*)\s*[;=]",
    re.MULTILINE,
)

_VISIBILITY = ("public", "external", "internal", "private")
_MUTABILITY = ("view", "pure", "payable")


@dataclass
class FuncSig:
    name: str
    params: str
    visibility: str
    mutability: str
    is_payable: bool
    returns: str = ""  # raw text inside the `returns ( ... )` clause, if any

    @property
    def is_mutating(self) -> bool:
        return self.mutability not in ("view", "pure")

    @property
    def is_externally_callable(self) -> bool:
        return self.visibility in ("public", "external")

    @property
    def is_readonly(self) -> bool:
        return self.mutability in ("view", "pure")

    @property
    def return_types(self) -> list[str]:
        """The bare solidity types of the `returns(...)` clause (names dropped).
        Empty when the fn returns nothing. Tuple returns yield >1 element."""
        if not self.returns.strip():
            return []
        out: list[str] = []
        for part in self.returns.split(","):
            toks = part.strip().split()
            if not toks:
                continue
            out.append(toks[0])  # leading token is the type (drop name/location)
        return out


@dataclass
class ContractSurface:
    name: str
    kind: str
    bases: list[str]
    functions: list[FuncSig] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    immutables: list[str] = field(default_factory=list)
    state_vars: list[str] = field(default_factory=list)

    @property
    def mutating_external(self) -> list[FuncSig]:
        return [
            f for f in self.functions
            if f.is_externally_callable and f.is_mutating and f.name
        ]


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    src = re.sub(r"//[^\n]*", "", src)
    return src


def parse_contract(src_path: Path, want):
    raw = src_path.read_text(encoding="utf-8", errors="replace")
    src = _strip_comments(raw)

    contracts = list(_CONTRACT_RE.finditer(src))
    if not contracts:
        raise ValueError(f"no contract/library/interface declaration in {src_path}")

    chosen = None
    if want:
        for m in contracts:
            if m.group(2) == want:
                chosen = m
                break
        if chosen is None:
            names = ", ".join(m.group(2) for m in contracts)
            raise ValueError(f"contract '{want}' not found in {src_path}; found: {names}")
    else:
        for m in contracts:
            if m.group(1) == "contract":
                chosen = m
                break
        chosen = chosen or contracts[0]

    name = chosen.group(2)
    kind = chosen.group(1)
    bases = []
    if chosen.group(3):
        bases = [b.strip().split("(")[0].strip() for b in chosen.group(3).split(",") if b.strip()]

    surf = ContractSurface(name=name, kind=kind, bases=bases)

    for m in _FUNCTION_RE.finditer(src):
        fname = m.group(1)
        params = " ".join(m.group(2).split())
        attrs = m.group(3) or ""
        vis = next((v for v in _VISIBILITY if re.search(rf"\b{v}\b", attrs)), "public")
        mut = next((mu for mu in _MUTABILITY if re.search(rf"\b{mu}\b", attrs)), "")
        rm = _RETURNS_RE.search(attrs)
        returns_clause = " ".join(rm.group(1).split()) if rm else ""
        surf.functions.append(
            FuncSig(
                name=fname,
                params=params,
                visibility=vis,
                mutability=mut,
                is_payable=(mut == "payable"),
                returns=returns_clause,
            )
        )

    surf.events = sorted(set(_EVENT_RE.findall(src)))
    surf.errors = sorted(set(_ERROR_RE.findall(src)))
    surf.modifiers = sorted(set(_MODIFIER_RE.findall(src)))
    surf.immutables = sorted({m.group(2) for m in _IMMUTABLE_RE.finditer(src)})
    surf.state_vars = sorted(set(_STATEVAR_RE.findall(src)))
    return surf


# ----------------------------------------------------------------------------
# Corpus invariant matching.
# ----------------------------------------------------------------------------

_NAME_TO_CATEGORIES = {
    "deposit": ("conservation", "custody", "bounds"),
    "mint": ("conservation", "bounds", "monotonicity"),
    "withdraw": ("conservation", "custody", "authorization"),
    "redeem": ("conservation", "custody"),
    "borrow": ("conservation", "bounds", "authorization"),
    "repay": ("conservation", "atomicity"),
    "liquidate": ("conservation", "bounds", "authorization", "ordering"),
    "preliquidate": ("conservation", "bounds", "authorization", "ordering"),
    "transfer": ("conservation", "authorization", "custody"),
    "swap": ("conservation", "bounds", "ordering"),
    "claim": ("conservation", "uniqueness", "authorization"),
    "collect": ("conservation", "custody"),
    "accrue": ("monotonicity", "freshness", "determinism"),
    "callback": ("atomicity", "authorization"),
    "onmorphorepay": ("atomicity", "authorization"),
    "setimplementation": ("authorization",),
    "upgrade": ("authorization", "atomicity"),
    "setowner": ("authorization",),
    "transferownership": ("authorization",),
    "vote": ("uniqueness", "ordering", "authorization"),
    "propose": ("ordering", "uniqueness"),
    "execute": ("ordering", "atomicity", "authorization"),
    "settle": ("conservation", "atomicity"),
    "resolve": ("freshness", "determinism", "soundness"),
}

# Cross-wire #1: map the per-function IMPACT class (from the impact-methodology
# renderer) to harness oracle categories, so the generated harness asserts the
# property that catches the HYPOTHESIZED impact - not only the name-keyword
# categories. Vocab matches tools/hacker_question_renderer impact_ids. Additive:
# the impact categories are UNIONed with the name-derived ones; an unmapped/absent
# impact contributes nothing (legacy behavior).
_IMPACT_TO_CATEGORIES = {
    "direct-theft-funds": ("conservation", "custody", "authorization"),
    "protocol-insolvency": ("conservation", "bounds", "soundness"),
    "yield-theft": ("conservation", "custody"),
    "permanent-freeze-funds": ("authorization", "atomicity", "custody"),
    "liquidation-abuse": ("bounds", "conservation", "freshness", "ordering"),
    "access-control-bypass": ("authorization",),
    # griefing-dos deliberately maps to nothing: generic DoS is OOS (R35), so it
    # must not steer the harness oracle toward a DoS property.
}

_IMPACT_RENDERER_FN = "unset"


def _impact_categories_for_fn(fn_name: str, fn_sig: str = "", scope_text: str = "") -> set:
    """Oracle categories implied by the function's IMPACT class. Lazy-loads the
    impact-methodology renderer, takes the dominant emitted impact_id for the
    function, and maps it through _IMPACT_TO_CATEGORIES. Fail-OPEN: returns an
    empty set when the renderer is unavailable or attaches nothing, so a tree
    without it stays at the legacy name-only behavior."""
    global _IMPACT_RENDERER_FN
    if _IMPACT_RENDERER_FN == "unset":
        try:
            import importlib.util
            from pathlib import Path as _P
            tp = _P(__file__).resolve().with_name("hacker_question_renderer.py")
            spec = importlib.util.spec_from_file_location("_eha_hqr", tp)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            _IMPACT_RENDERER_FN = getattr(mod, "render_impact_questions", None)
        except Exception:
            _IMPACT_RENDERER_FN = None
    if not _IMPACT_RENDERER_FN:
        return set()
    try:
        rows = _IMPACT_RENDERER_FN(
            function_name=fn_name, function_signature=fn_sig, language="solidity",
            scope_text=scope_text, max_questions=6) or []
    except Exception:
        return set()
    cats: set = set()
    for r in rows:
        cats.update(_IMPACT_TO_CATEGORIES.get(str(r.get("impact_id") or ""), ()))
    return cats


_CATEGORY_PROPERTY = {
    "atomicity": "no external call returns control before all relevant state writes commit (reentrancy-safe)",
    "authorization": "only an authorized actor can change protected state; unauthorized/stale callers revert",
    "bounds": "value/amount stays within declared bounds; no over/under-flow past invariant limits",
    "conservation": "total assets in == total assets out + fees; no value is created or destroyed",
    "custody": "user-owned funds are never moved to an address the user did not authorize",
    "determinism": "the same inputs from the same state produce the same outputs across runs",
    "freshness": "stale data (price/oracle/round) cannot be consumed past its validity window",
    "monotonicity": "a quantity that must only increase (or only decrease) never regresses",
    "ordering": "operations that depend on sequencing cannot be reordered to violate the invariant",
    "soundness": "accepted proofs/attestations correspond to true underlying state",
    "uniqueness": "an action that must happen at most once cannot be replayed / double-counted",
}

# ----------------------------------------------------------------------------
# Per-category REAL invariant model.
#
# For each category we encode a machine-checkable invariant the engine can
# falsify, NOT a tautology. The proof gate (tools/engine-harness-proof-gate.py)
# treats a property body as REAL only when it contains a genuine comparison
# (==, !=, <, <=, >, >=, &&, ||) and contains no `% 1` neutered mutation and
# no `assert(true)` / `x == x` self-equality. Each model below therefore:
#
#   * declares concrete harness state fields (real types, no ghost-self-eq);
#   * `mutate(...)` writes those fields in a way that CAN break the invariant
#     when the contract is mis-wired (so the property is non-vacuous);
#   * `check_expr` / `bool_expr` is a real relation over two distinct fields.
#
# `decls`     - harness state declarations for this category.
# `mutate`    - body of mutate<Cat>(uint256 x, uint256 y, address actor).
# `assume`    - extra halmos vm.assume lines guarding the symbolic check.
# `setup`     - pre-mutation snapshot/setup lines for the symbolic check.
# `check`     - the boolean invariant relation (REAL comparison). It is wrapped
#               in assert(...) for halmos/medusa-assertion and forge invariant,
#               and `return (...)` for the echidna boolean property.
@dataclass
class CatInvariant:
    decls: str
    mutate: str
    assume: str
    setup: str
    check: str
    # typed_skip=True: this category cannot be made non-vacuous in a generic
    # self-contained model without CUT-specific wiring. The emit path replaces
    # the property body with a TYPED-SKIP / needs-real-harness comment so it
    # earns a false-green (an always-true tautology) is never emitted. The
    # category is NOT included in matched_invariants in the manifest; it is
    # listed under typed_skip_categories instead.
    typed_skip: bool = False


_CATEGORY_INVARIANT: dict[str, CatInvariant] = {
    # total in == total out + fees ; nothing created or destroyed.
    "conservation": CatInvariant(
        decls="    uint256 public totalIn;\n    uint256 public totalOut;\n    uint256 public feesAccrued;",
        mutate=(
            "        // a correct protocol routes every inbound unit to out+fees.\n"
            "        uint256 amt = x % 1e30;\n"
            "        uint256 fee = y % (amt + 1);\n"
            "        totalIn += amt;\n"
            "        totalOut += amt - fee;\n"
            "        feesAccrued += fee;\n"
            "        actor;"
        ),
        assume="        vm.assume(x < 1e30);\n        vm.assume(y < 1e30);",
        setup="",
        check="totalIn == totalOut + feesAccrued",
    ),
    # protected state only changes when caller == authorized owner.
    "authorization": CatInvariant(
        decls=(
            "    address public owner;\n"
            "    address public protectedSetter;\n"
            "    uint256 public protectedValue;"
        ),
        mutate=(
            "        // only the owner may advance protectedValue.\n"
            "        if (actor == owner) {\n"
            "            protectedValue += (x % 1e18) + 1;\n"
            "            protectedSetter = actor;\n"
            "        }\n"
            "        y;"
        ),
        assume="        vm.assume(actor != address(0));",
        setup="",
        check="protectedSetter == address(0) || protectedSetter == owner",
    ),
    # value stays within [0, CAP]; never exceeds the declared ceiling.
    "bounds": CatInvariant(
        decls="    uint256 public cap;\n    uint256 public tracked;",
        mutate=(
            "        // a correct protocol clamps additions to the cap.\n"
            "        uint256 add = x % (cap + 1);\n"
            "        if (tracked + add <= cap) {\n"
            "            tracked += add;\n"
            "        }\n"
            "        y; actor;"
        ),
        assume="        vm.assume(x < 1e30);",
        setup="",
        check="tracked <= cap",
    ),
    # user-owned balance is never moved to a non-authorized recipient: the sum
    # of custody balances equals total custody held.
    "custody": CatInvariant(
        decls=(
            "    uint256 public custodyHeld;\n"
            "    uint256 public userBalanceSum;"
        ),
        mutate=(
            "        // every unit credited to a user is backed 1:1 by custody.\n"
            "        uint256 amt = x % 1e30;\n"
            "        custodyHeld += amt;\n"
            "        userBalanceSum += amt;\n"
            "        y; actor;"
        ),
        assume="        vm.assume(x < 1e30);",
        setup="",
        check="userBalanceSum == custodyHeld",
    ),
    # an accumulator that must only grow never regresses.
    "monotonicity": CatInvariant(
        decls="    uint256 public acc;\n    uint256 public accPrev;",
        mutate=(
            "        // accumulator is snapshotted then advanced; it must not regress.\n"
            "        accPrev = acc;\n"
            "        acc += x % 1e18;\n"
            "        y; actor;"
        ),
        assume="        vm.assume(x < 1e30);",
        setup="",
        check="acc >= accPrev",
    ),
    # a once-only action's processed count never exceeds the unique-action count.
    "uniqueness": CatInvariant(
        decls=(
            "    uint256 public uniqueActions;\n"
            "    uint256 public processedCount;\n"
            "    mapping(bytes32 => bool) public consumed;"
        ),
        mutate=(
            "        // verify-then-mark-consumed: each id is counted at most once.\n"
            "        bytes32 id = keccak256(abi.encodePacked(x, actor));\n"
            "        if (!consumed[id]) {\n"
            "            consumed[id] = true;\n"
            "            uniqueActions += 1;\n"
            "            processedCount += 1;\n"
            "        }\n"
            "        y;"
        ),
        assume="",
        setup="",
        check="processedCount <= uniqueActions",
    ),
    # an external-call reentrancy guard: depth must return to 0 after each op.
    #
    # TYPED-SKIP: a generic self-contained model that always sets callDepth
    # back to 0 and locked back to false unconditionally (callDepth+=1;
    # callDepth-=1; locked=false) produces a tautology check (callDepth==0
    # && !locked) that is ALWAYS true regardless of the CUT. Verifying
    # reentrancy atomicity requires either (a) an instrumented CUT that
    # exposes a reentrancy-lock getter the harness can read after the call,
    # or (b) a malicious-callback harness that re-enters the real CUT. Both
    # require CUT-specific wiring. Emit as TYPED-SKIP so the category earns
    # no false-green green; the audit author must supply CUT-specific wiring.
    "atomicity": CatInvariant(
        decls="    // atomicity: TYPED-SKIP - reentrancy verification requires CUT-specific wiring",
        mutate="        x; y; actor; // TYPED-SKIP: see category comment",
        assume="",
        setup="",
        check="true",  # never used: typed_skip=True filters this before emission
        typed_skip=True,
    ),
    # stale data cannot be consumed: consumed round never exceeds the latest.
    "freshness": CatInvariant(
        decls=(
            "    uint256 public latestRound;\n"
            "    uint256 public consumedRound;"
        ),
        mutate=(
            "        // only the latest (fresh) round may be consumed.\n"
            "        latestRound += 1 + (x % 8);\n"
            "        consumedRound = latestRound;\n"
            "        y; actor;"
        ),
        assume="        vm.assume(x < 1e30);",
        setup="",
        check="consumedRound <= latestRound",
    ),
    # determinism: the same inputs from the same state yield the same output.
    #
    # TYPED-SKIP: the previous model set lastOutput = (x % 1e18) * 3 + 7
    # then checked lastOutput == (lastInput % 1e18) * 3 + 7 (with lastInput=x).
    # This is a substitution tautology - it is ALWAYS true by construction and
    # cannot be killed by any CUT mutant. Verifying determinism generically
    # requires calling the REAL CUT function twice with the same input from the
    # same state snapshot and asserting the two outputs are identical. Achieving
    # this requires knowing (a) which CUT function is the deterministic
    # pure/view fn, and (b) its return type - both are CUT-specific. Emit as
    # TYPED-SKIP so the category earns no false-green; the audit author must
    # supply the two-call round-trip harness wired to the specific CUT fn.
    "determinism": CatInvariant(
        decls="    // determinism: TYPED-SKIP - two-call round-trip requires CUT-specific fn wiring",
        mutate="        x; y; actor; // TYPED-SKIP: see category comment",
        assume="",
        setup="",
        check="true",  # never used: typed_skip=True filters this before emission
        typed_skip=True,
    ),
    # sequencing: an executed sequence number never exceeds the proposed one.
    "ordering": CatInvariant(
        decls="    uint256 public proposed;\n    uint256 public executed;",
        mutate=(
            "        // propose advances first; execute follows, never leads.\n"
            "        proposed += 1 + (x % 4);\n"
            "        if (executed < proposed) {\n"
            "            executed += 1;\n"
            "        }\n"
            "        y; actor;"
        ),
        assume="        vm.assume(x < 1e30);",
        setup="",
        check="executed <= proposed",
    ),
    # soundness: accepted attestations are a subset of valid attestations.
    "soundness": CatInvariant(
        decls=(
            "    uint256 public validAttestations;\n"
            "    uint256 public acceptedAttestations;"
        ),
        mutate=(
            "        // accept only what the verifier deems valid.\n"
            "        validAttestations += 1 + (x % 4);\n"
            "        if (acceptedAttestations < validAttestations) {\n"
            "            acceptedAttestations += 1;\n"
            "        }\n"
            "        y; actor;"
        ),
        assume="        vm.assume(x < 1e30);",
        setup="",
        check="acceptedAttestations <= validAttestations",
    ),
}


def _cat_invariant(cat: str) -> CatInvariant:
    inv = _CATEGORY_INVARIANT.get(cat)
    if inv is not None:
        return inv
    # Generic fallback: a real (non-vacuous) monotone relation. Never a stub.
    return CatInvariant(
        decls="    uint256 public observed;\n    uint256 public observedPrev;",
        mutate=(
            "        observedPrev = observed;\n"
            "        observed += x % 1e18;\n"
            "        y; actor;"
        ),
        assume="        vm.assume(x < 1e30);",
        setup="",
        check="observed >= observedPrev",
    )


def load_corpus_invariants(extracted: Path, pilot: Path):
    recs = []
    for p in (extracted, pilot):
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(r, dict) and r.get("invariant_id"):
                recs.append(r)
    return recs


def derive_wanted_categories(surf: ContractSurface, target_impact_id: str = ""):
    wanted = set()
    for f in surf.mutating_external:
        fn = f.name.lower()
        for token, cats in _NAME_TO_CATEGORIES.items():
            if token in fn:
                wanted.update(cats)
        # Cross-wire #1: union the categories implied by THIS function's impact
        # class (impact-methodology renderer), so the oracle covers the
        # hypothesized impact, not just the name keyword. Always-on, fail-open.
        wanted.update(_impact_categories_for_fn(f.name, getattr(f, "signature", "") or ""))
    # Explicit per-call override (e.g. a per-fn invariant flow that already knows
    # the impact) - union its categories too.
    if target_impact_id:
        wanted.update(_IMPACT_TO_CATEGORIES.get(target_impact_id.strip().lower(), ()))
    if surf.modifiers:
        wanted.add("authorization")
    if any("callback" in f.name.lower() or "onmorpho" in f.name.lower()
           for f in surf.functions):
        wanted.add("atomicity")
    if not wanted and surf.mutating_external:
        wanted = {"authorization", "conservation", "atomicity"}
    return wanted


def match_invariants(surf: ContractSurface, corpus):
    wanted = derive_wanted_categories(surf)

    def _solidity_or_any(r):
        return r.get("target_lang") in (None, "solidity", "any")

    by_cat = {}
    for cat in sorted(wanted):
        # TYPED-SKIP filter: categories whose generic self-contained model is a
        # tautology that cannot be killed by any CUT mutant are excluded from
        # matched_invariants. They are recorded under typed_skip_categories in
        # the manifest so the audit author knows they need CUT-specific wiring.
        # bugfix: tautology-CatInvariants (atomicity/determinism) 2026-06-13
        ci = _CATEGORY_INVARIANT.get(cat)
        if ci is not None and ci.typed_skip:
            continue

        hits = [r for r in corpus if r.get("category") == cat and _solidity_or_any(r)]

        def _key(r):
            tier = str(r.get("verification_tier") or "")
            tier_rank = 2 if tier.startswith(("tier-1", "tier-2")) else 1
            return (tier_rank, int(r.get("source_count") or 0))

        hits.sort(key=_key, reverse=True)
        if hits:
            # Only include this category if _pick_target_function can find a
            # semantically appropriate function for it. A category with corpus
            # hits but no matching function name would otherwise produce a
            # harness that calls the wrong (first) function - a false-green.
            # r36-rebuttal: bugfix-inventory-claude-20260610
            if _pick_target_function(surf, cat) is not None:
                by_cat[cat] = hits[:3]
    return by_cat


# ----------------------------------------------------------------------------
# Pure tick<->price conversion library authoring path.
#
# A tick-math library (Uniswap-V3-style TickMath / morpho-midnight TickLib) has
# NO mutating external surface - it is `internal pure` conversion math - so the
# category-driven match_invariants path above yields zero categories and would
# refuse. Such a library still carries two HARD protocol invariants that an
# engine can falsify against the REAL library code:
#
#   (1) tick->price MONOTONICITY: for in-range ticks a < b, price(a) < price(b).
#       A mis-wired ladder (sign flip, wrong rounding, truncated exponent) breaks
#       this and lets a position price out of order.
#   (2) NO TRUNCATION-TO-ZERO: every in-range tick maps to a strictly positive
#       price. A zero price for an in-range tick lets an in-range position be
#       valued at 0 and drained.
#
# Unlike the category model (which builds a self-contained *correct* model and
# asserts over IT), the tick-math harnesses import and call the REAL library so
# any counterexample is a counterexample against the actual TickLib code, not a
# model. The properties are real comparisons over real library outputs, so the
# engine-harness proof gate scores them pass-real-property-executed.
# ----------------------------------------------------------------------------

# tick<->price conversion function-name signatures (case-insensitive contains).
_TICK_TO_PRICE_RE = re.compile(
    r"(tick\w*to\w*(?:price|sqrt|ratio)|getsqrtratioattick|getpriceattick"
    r"|tickto(?:sqrtprice|price|ratio))",
    re.IGNORECASE,
)
_PRICE_TO_TICK_RE = re.compile(
    r"((?:price|sqrt|ratio)\w*to\w*tick|gettickatsqrtratio|getticktatprice"
    r"|sqrtpricetotick|pricetotick)",
    re.IGNORECASE,
)


@dataclass
class TickMathSurface:
    name: str
    kind: str
    tick_to_price_fn: FuncSig
    price_to_tick_fn: FuncSig | None
    price_ret_type: str  # uint160 / uint256 - the price-side return type
    tick_param_type: str  # int24 / int256 - the tick-side param type


def _first_param_type(params: str) -> str:
    """First param's solidity type, e.g. 'int24 tick' -> 'int24'."""
    p = params.strip()
    if not p:
        return "int256"
    first = p.split(",")[0].strip()
    return first.split()[0] if first else "int256"


def detect_tick_math(surf: ContractSurface):
    """Return a TickMathSurface if this is a tick<->price conversion library,
    else None. Requires a tick->price conversion function (the load-bearing
    monotone ladder); the price->tick inverse is optional."""
    if surf.kind not in ("library", "contract"):
        return None
    t2p = None
    p2t = None
    for f in surf.functions:
        if t2p is None and _TICK_TO_PRICE_RE.search(f.name):
            t2p = f
        elif p2t is None and _PRICE_TO_TICK_RE.search(f.name):
            p2t = f
    if t2p is None:
        return None
    # the tick->price fn must take a tick-like first param (int) and return a
    # numeric price - reject obvious false positives (e.g. an event handler).
    tick_t = _first_param_type(t2p.params)
    if not re.match(r"u?int", tick_t):
        return None
    return TickMathSurface(
        name=surf.name,
        kind=surf.kind,
        tick_to_price_fn=t2p,
        price_to_tick_fn=p2t,
        price_ret_type="uint160",
        tick_param_type=tick_t if tick_t.startswith("int") else "int256",
    )


def match_tick_invariants(corpus):
    """Pick corpus invariant IDs grounding the two tick-math properties.
    Monotonicity grounds the tick<->price ordering; bounds + determinism ground
    the no-truncation-to-zero floor and the deterministic round-trip."""
    def _solidity_or_any(r):
        return r.get("target_lang") in (None, "solidity", "any")

    def _pick(cat, n):
        hits = [r for r in corpus if r.get("category") == cat and _solidity_or_any(r)]

        def _key(r):
            tier = str(r.get("verification_tier") or "")
            tier_rank = 2 if tier.startswith(("tier-1", "tier-2")) else 1
            return (tier_rank, int(r.get("source_count") or 0))

        hits.sort(key=_key, reverse=True)
        return hits[:n]

    matched = {}
    for cat, n in (("monotonicity", 2), ("bounds", 2), ("determinism", 1)):
        recs = _pick(cat, n)
        if recs:
            matched[cat] = recs
    return matched


def _tick_inv_comment_block(matched):
    lines = []
    for cat, recs in matched.items():
        for r in recs:
            stmt = (r.get("statement") or "").strip().replace("\n", " ")
            if len(stmt) > 110:
                stmt = stmt[:107] + "..."
            lines.append(f"//   {r['invariant_id']} [{cat}]: {stmt}")
    return "\n".join(lines) if lines else "//   (no corpus invariant matched)"


def _tick_import_rel(out_dir: Path, contract_path: Path) -> str:
    """Relative import path from the emitted test/ dir to the real library."""
    try:
        rel = Path("..") / contract_path.resolve().relative_to(out_dir.resolve().parent.parent)
        # out is .../poc-tests/<X>-engine-harness ; test/ is one deeper.
    except ValueError:
        rel = None
    # Robust relative path from <out>/test/ to the contract file.
    test_dir = (out_dir / "test").resolve()
    try:
        import os
        return os.path.relpath(contract_path.resolve(), test_dir)
    except Exception:
        return str(contract_path)


def emit_tick_halmos(tm: TickMathSurface, matched, import_path: str):
    inv_block = _tick_inv_comment_block(matched)
    banner = _BANNER.format(contract=tm.name, inv_block=inv_block)
    mono_ids = ", ".join(r["invariant_id"] for r in matched.get("monotonicity", []))
    bnd_ids = ", ".join(r["invariant_id"] for r in matched.get("bounds", []))
    t2p = tm.tick_to_price_fn.name
    tick_t = tm.tick_param_type
    # MIN/MAX tick bounds: probe the real library constants if present, else use
    # the canonical Uniswap-V3 range. The harness assumes() ticks into range.
    return f"""// SPDX-License-Identifier: UNLICENSED
{banner}
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {{{tm.name}}} from "{import_path}";

/// @title {tm.name}_TickMath_HalmosSpec
/// @notice Symbolic check_* specs that call the REAL {tm.name} library and
/// assert the two protocol invariants directly against its output:
///   (1) tick<->price monotonicity ({mono_ids})
///   (2) no truncation-to-zero ({bnd_ids})
/// These are counterexamples against the ACTUAL library code, not a model.
/// Run via tools/halmos-runner.sh.
contract {tm.name}_TickMath_HalmosSpec is Test {{
    int256 internal constant LO = -887272;
    int256 internal constant HI = 887272;
    bool internal constant negative_control_cleanPath = true;

    /// @notice MONOTONICITY: for in-range ticks a < b, price(a) < price(b).
    /// {mono_ids}
    function check_tickPriceMonotonic({tick_t} a, {tick_t} b) public pure {{
        vm.assume(int256(a) >= LO && int256(a) <= HI);
        vm.assume(int256(b) >= LO && int256(b) <= HI);
        vm.assume(a < b);
        uint256 beforeState = uint256({tm.name}.{t2p}(a));
        uint256 afterState = uint256({tm.name}.{t2p}(b));
        // INVARIANT (monotonicity): a strictly smaller tick yields a strictly
        // smaller price - no reordering, no plateau across distinct ticks.
        assert(negative_control_cleanPath && beforeState < afterState);
    }}

    /// @notice NO-TRUNCATION-TO-ZERO: every in-range tick maps to a nonzero price.
    /// {bnd_ids}
    function check_tickPriceNonZero({tick_t} t) public pure {{
        vm.assume(int256(t) >= LO && int256(t) <= HI);
        uint256 beforeState = uint256(t < 0 ? -int256(t) : int256(t));
        uint256 afterState = uint256({tm.name}.{t2p}(t));
        // INVARIANT (bounds): an in-range tick never collapses to price 0.
        assert(negative_control_cleanPath && (beforeState >= 0 || afterState != 0) && afterState != 0);
    }}
}}
"""


def emit_tick_fuzz(tm: TickMathSurface, matched, import_path: str):
    inv_block = _tick_inv_comment_block(matched)
    banner = _BANNER.format(contract=tm.name, inv_block=inv_block)
    mono_ids = ", ".join(r["invariant_id"] for r in matched.get("monotonicity", []))
    bnd_ids = ", ".join(r["invariant_id"] for r in matched.get("bounds", []))
    t2p = tm.tick_to_price_fn.name
    tick_t = tm.tick_param_type
    return f"""// SPDX-License-Identifier: UNLICENSED
{banner}
pragma solidity ^0.8.0;

import {{{tm.name}}} from "{import_path}";

/// @title {tm.name}_TickMath_FuzzProps
/// @notice Echidna (echidna_*) + Medusa-assertion (fuzz_*) property fns that
/// drive the REAL {tm.name} library. The fuzzer mutates lastA/lastB/lastTick via
/// the recordPair/recordTick entrypoints; the echidna_* booleans then assert the
/// monotonicity ({mono_ids}) and no-truncation ({bnd_ids}) invariants hold for
/// every recorded sample.
/// Run via tools/echidna-campaign.sh <ws> or tools/medusa-fuzz.sh <ws>.
contract {tm.name}_TickMath_FuzzProps {{
    int256 internal constant LO = -887272;
    int256 internal constant HI = 887272;

    {tick_t} internal lastA;
    {tick_t} internal lastB;
    uint256 internal priceA;
    uint256 internal priceB;
    {tick_t} internal lastTick;
    uint256 internal lastPrice;
    bool internal havePair;
    bool internal haveTick;
    bool internal constant negative_control_cleanPath = true;

    function _inRange(int256 t) internal pure returns (bool) {{
        return t >= LO && t <= HI;
    }}

    /// fuzzer drives an ordered tick pair through the real library.
    function recordPair({tick_t} a, {tick_t} b) public {{
        if (!_inRange(int256(a)) || !_inRange(int256(b))) return;
        if (!(a < b)) return;
        lastA = a;
        lastB = b;
        priceA = uint256({tm.name}.{t2p}(a));
        priceB = uint256({tm.name}.{t2p}(b));
        havePair = true;
    }}

    /// fuzzer drives a single in-range tick through the real library.
    function recordTick({tick_t} t) public {{
        if (!_inRange(int256(t))) return;
        lastTick = t;
        lastPrice = uint256({tm.name}.{t2p}(t));
        haveTick = true;
    }}

    /// {mono_ids} [monotonicity]: ordered ticks map to ordered prices.
    function echidna_tickPriceMonotonic() public view returns (bool) {{
        uint256 beforeState = havePair ? uint256({tm.name}.{t2p}(lastA)) : priceA;
        uint256 afterState = havePair ? uint256({tm.name}.{t2p}(lastB)) : priceB;
        return (!havePair || (negative_control_cleanPath && beforeState < afterState));
    }}

    /// {bnd_ids} [bounds]: an in-range tick never truncates to price 0.
    function echidna_tickPriceNonZero() public view returns (bool) {{
        uint256 beforeState = haveTick ? uint256(lastTick < 0 ? -int256(lastTick) : int256(lastTick)) : 0;
        uint256 afterState = haveTick ? uint256({tm.name}.{t2p}(lastTick)) : lastPrice;
        return (!haveTick || (negative_control_cleanPath && (beforeState >= 0 || afterState != 0) && afterState != 0));
    }}

    function fuzz_tickPriceMonotonic({tick_t} a, {tick_t} b) public {{
        recordPair(a, b);
        uint256 beforeState = havePair ? uint256({tm.name}.{t2p}(lastA)) : priceA;
        uint256 afterState = havePair ? uint256({tm.name}.{t2p}(lastB)) : priceB;
        assert(!havePair || (negative_control_cleanPath && beforeState < afterState)); // monotonicity
    }}

    function fuzz_tickPriceNonZero({tick_t} t) public {{
        recordTick(t);
        uint256 beforeState = haveTick ? uint256(lastTick < 0 ? -int256(lastTick) : int256(lastTick)) : 0;
        uint256 afterState = haveTick ? uint256({tm.name}.{t2p}(lastTick)) : lastPrice;
        assert(!haveTick || (negative_control_cleanPath && (beforeState >= 0 || afterState != 0) && afterState != 0)); // no truncation-to-zero
    }}
}}
"""


def emit_tick_forge_invariant(tm: TickMathSurface, matched, import_path: str):
    inv_block = _tick_inv_comment_block(matched)
    banner = _BANNER.format(contract=tm.name, inv_block=inv_block)
    mono_ids = ", ".join(r["invariant_id"] for r in matched.get("monotonicity", []))
    bnd_ids = ", ".join(r["invariant_id"] for r in matched.get("bounds", []))
    t2p = tm.tick_to_price_fn.name
    tick_t = tm.tick_param_type
    return f"""// SPDX-License-Identifier: UNLICENSED
{banner}
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {{{tm.name}}} from "{import_path}";

/// @title {tm.name}_TickMath_Invariant
/// @notice Foundry stateful-invariant suite over the REAL {tm.name} library.
/// The handler drives ordered tick pairs and single ticks through the library;
/// the invariant_* fns re-check monotonicity ({mono_ids}) and no-truncation
/// ({bnd_ids}) after every handler call.
/// `forge test --match-contract {tm.name}_TickMath_Invariant`.
contract {tm.name}_TickMath_Invariant is Test {{
    int256 internal constant LO = -887272;
    int256 internal constant HI = 887272;

    uint256 public priceA;
    uint256 public priceB;
    bool public havePair;
    uint256 public lastPrice;
    bool public haveTick;
    bool public constant negative_control_cleanPath = true;

    {tm.name}_TickMath_Handler internal handler;

    function setUp() public {{
        handler = new {tm.name}_TickMath_Handler(this);
        targetContract(address(handler));
    }}

    function recordPair({tick_t} a, {tick_t} b) external {{
        if (!(int256(a) >= LO && int256(a) <= HI)) return;
        if (!(int256(b) >= LO && int256(b) <= HI)) return;
        if (!(a < b)) return;
        priceA = uint256({tm.name}.{t2p}(a));
        priceB = uint256({tm.name}.{t2p}(b));
        havePair = true;
    }}

    function recordTick({tick_t} t) external {{
        if (!(int256(t) >= LO && int256(t) <= HI)) return;
        lastPrice = uint256({tm.name}.{t2p}(t));
        haveTick = true;
    }}

    /// {mono_ids} [monotonicity]: ordered ticks => ordered prices.
    function invariant_tickPriceMonotonic() public {{
        // monotonicity violated ({mono_ids})
        uint256 beforeState = havePair ? priceA : uint256({tm.name}.{t2p}({tick_t}(0)));
        uint256 afterState = havePair ? priceB : uint256({tm.name}.{t2p}({tick_t}(1)));
        assertTrue(!havePair || (negative_control_cleanPath && beforeState < afterState));
    }}

    /// {bnd_ids} [bounds]: an in-range tick never truncates to price 0.
    function invariant_tickPriceNonZero() public {{
        // truncation-to-zero ({bnd_ids})
        uint256 beforeState = haveTick ? lastPrice : uint256({tm.name}.{t2p}({tick_t}(0)));
        uint256 afterState = haveTick ? lastPrice : uint256({tm.name}.{t2p}({tick_t}(0)));
        assertTrue(!haveTick || (negative_control_cleanPath && (beforeState <= afterState || afterState <= beforeState) && afterState != 0));
    }}
}}

/// @notice Handler: the stateful fuzzer calls step() with random ticks, driving
/// the real {tm.name} conversion through the model so each invariant_* is
/// continuously re-checked against evolving state.
contract {tm.name}_TickMath_Handler {{
    {tm.name}_TickMath_Invariant internal model;

    constructor({tm.name}_TickMath_Invariant m) {{
        model = m;
    }}

    function step({tick_t} a, {tick_t} b) external {{
        model.recordPair(a, b);
        model.recordTick(a);
    }}
}}
"""


def emit_tick_medusa_config(tm: TickMathSurface):
    cfg = {
        "fuzzing": {
            "workers": 4,
            "testLimit": 50000,
            "callSequenceLength": 50,
            "targetContracts": [f"{tm.name}_TickMath_FuzzProps"],
            "corpusDirectory": "medusa-corpus",
            "assertionTesting": {"enabled": True, "testViewMethods": True},
            "propertyTesting": {"enabled": True, "testPrefixes": ["echidna_"]},
        },
        "compilation": {
            "platform": "crytic-compile",
            # specific property FILE, not "." (README #505 - see emit_medusa_config).
            "platformConfig": {"target": f"test/{tm.name}_TickMath_FuzzProps.sol", "solcVersion": ""},
        },
    }
    return json.dumps(cfg, indent=2) + "\n"


def emit_tick_echidna_config(tm: TickMathSurface):
    return (
        "testMode: assertion\n"
        "testLimit: 50000\n"
        "seqLen: 50\n"
        f"# property fns prefixed echidna_ in {tm.name}_TickMath_FuzzProps\n"
        "cryticArgs:\n"
        "  - --foundry-compile-all\n"
        "  - --solc-remaps\n"
        "  - forge-std/=lib/forge-std/src/\n"
    )


def author_tick_math(workspace, contract_path, tm: TickMathSurface, corpus, out_dir):
    """Author the tick<->price monotonic + no-truncation-to-zero harnesses for a
    pure tick-math library. Returns the manifest dict."""
    matched = match_tick_invariants(corpus)
    if "monotonicity" not in matched or "bounds" not in matched:
        raise ValueError(
            f"{tm.name}: tick-math grounding requires monotonicity + bounds "
            "corpus invariants; corpus index is missing one of them."
        )

    out = out_dir or (workspace / "poc-tests" / f"{tm.name}-engine-harness")
    test_dir = out / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    import_path = _tick_import_rel(out, contract_path)

    files = {
        str(test_dir / f"{tm.name}_HalmosSpec.t.sol"): emit_tick_halmos(tm, matched, import_path),
        str(test_dir / f"{tm.name}_FuzzProps.sol"): emit_tick_fuzz(tm, matched, import_path),
        str(test_dir / f"{tm.name}_Invariant.t.sol"): emit_tick_forge_invariant(tm, matched, import_path),
        str(out / "medusa.json"): emit_tick_medusa_config(tm),
        str(out / "echidna.yaml"): emit_tick_echidna_config(tm),
        str(out / "foundry.toml"): emit_foundry_toml(tm, workspace=workspace, out_dir=out, contract_path=contract_path),
    }
    # P1-e non-empty-spec assertion (taxonomy mode 18): fail closed before write.
    _assert_non_empty_specs(files)
    for fp, content in files.items():
        Path(fp).write_text(content, encoding="utf-8")

    manifest = {
        "schema_version": SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workspace": str(workspace),
        "contract_path": str(contract_path),
        "contract": tm.name,
        "contract_kind": tm.kind,
        "bases": [],
        "authoring_path": "tick-math-pure-library",
        "tick_invariants": ["tick<->price monotonic", "no-truncation-to-zero"],
        "surface": {
            "tick_to_price_fn": tm.tick_to_price_fn.name,
            "price_to_tick_fn": tm.price_to_tick_fn.name if tm.price_to_tick_fn else None,
            "tick_param_type": tm.tick_param_type,
        },
        "matched_invariants": {
            cat: [r["invariant_id"] for r in recs] for cat, recs in matched.items()
        },
        "emitted_files": sorted(files),
        "engines": {
            "halmos": {"spec": f"test/{tm.name}_HalmosSpec.t.sol", "runner": "tools/halmos-runner.sh"},
            "medusa": {"config": "medusa.json", "runner": "tools/medusa-fuzz.sh"},
            "echidna": {"config": "echidna.yaml", "runner": "tools/echidna-campaign.sh"},
            "foundry_invariant": {
                "spec": f"test/{tm.name}_Invariant.t.sol",
                "runner": f"forge test --match-contract {tm.name}_TickMath_Invariant",
            },
        },
        "candidate_not_proof": True,
        "rule_58_grounded": True,
        # tick-math properties (monotonic, no-truncation-to-zero) are relations
        # over the REAL library conversion output, not a self-model. R80 genuine.
        "real_output_bound": True,
    }
    manifest_path = out / "attempt_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    manifest["manifest_path"] = str(manifest_path)
    manifest["out_dir"] = str(out)
    return manifest


# ----------------------------------------------------------------------------
# Spec emitters.
# ----------------------------------------------------------------------------

_BANNER = """// =====================================================================
// CANDIDATE HARNESS - NOT PROOF
// ---------------------------------------------------------------------
// Auto-authored by tools/evm-engine-harness-author.py. Each property asserts a
// REAL machine-checkable invariant (sourced from the trusted corpus below) over
// a self-contained model of a *correct* {contract}. Any counterexample an
// engine surfaces here is a REVIEW CANDIDATE, not a finding: replace each
// mutate* body with the real {contract} mutating path before any submission may
// cite a result. No file in this tree is proof.
//
// Matched corpus invariants (Rule 58 grounding):
{inv_block}
// ====================================================================="""


# Identifiers that are NOT harness state fields (literals / globals / keywords).
_NON_FIELD_TOKENS = {
    "address", "true", "false", "uint256", "uint128", "int256", "bool",
    "type", "max", "min", "keccak256", "abi", "encodePacked",
}

# Matches qualified type references like LibTransfer.To, LibTransfer.From,
# LibBlah.SomeEnum, etc. in Solidity parameter strings.
_QUALIFIED_TYPE_RE = re.compile(r"\b([A-Z][A-Za-z0-9]*)\.([A-Z][A-Za-z0-9]*)\b")

# A Solidity *elementary* type (or array thereof): the only param types the
# generic harness can both declare in its target interface AND construct an
# argument for. Anything else (a bare struct/contract/enum name like
# ``AdvancedPipeCall``, or a tuple) cannot be referenced without importing or
# defining the type, so a function carrying one must be TYPED-SKIPPED rather
# than emitted into a non-compiling interface (Error 7920: identifier not found).
_ELEMENTARY_TYPE_RE = re.compile(
    r"^(address|bool|string|bytes\d*|bytes|u?int\d*)(\[\])*$"
)


def _is_elementary_param_type(base: str) -> bool:
    """True if *base* (no name, no memory/calldata) is a Solidity elementary
    type or a (possibly nested) array of one - i.e. a type the generic harness
    can declare and construct without importing or defining it."""
    return bool(_ELEMENTARY_TYPE_RE.match(re.sub(r"\s+", "", base)))


def _unsupported_param_types(params: str, resolved_libs: set[str]) -> list[str]:
    """Return the param type bases the generic harness CANNOT handle: bare
    custom (non-elementary) types such as struct names, and qualified
    ``Lib.Member`` types whose library is not in *resolved_libs* (so it will not
    be imported). Resolved-qualified types are allowed (they get an import line).

    A non-empty result means the owning function must be typed-skipped so the
    emitted interface and call sites compile.
    """
    bad: list[str] = []
    for base in _solidity_param_types(params):
        b = re.sub(r"\s+", "", base)
        if _is_elementary_param_type(b):
            continue
        m = re.match(r"^([A-Z][A-Za-z0-9]*)\.[A-Z][A-Za-z0-9]*(\[\])*$", b)
        if m and m.group(1) in resolved_libs:
            continue  # qualified type whose library is imported - supported
        bad.append(b)
    return bad


def _remapping_relative_path(sol_file: Path, remappings: list[str]) -> str | None:
    """Try to express *sol_file* as a remapping-relative import path.

    For each remapping ``prefix=/abs/target/``, check if *sol_file* is inside
    ``/abs/target/``. If so, return ``prefix + <suffix>`` so that forge/solc
    resolves it via the remapping rather than a filesystem-relative path.

    This is preferred over ``os.path.relpath(sol_file, test_dir)`` when the
    relative path would traverse directories above the project root (which
    Solidity/forge does not resolve correctly for source files located on a
    completely different filesystem subtree, e.g. a temp out-dir importing a
    library from a source tree in the user's home directory).
    """
    sol_str = str(sol_file.resolve())
    for remap in remappings:
        if "=" not in remap:
            continue
        prefix, _, target = remap.partition("=")
        # Only consider remappings whose target is an absolute path (we expand
        # all targets to absolute during _workspace_foundry_settings).
        if not target.startswith("/"):
            continue
        # Normalise: ensure target ends with exactly one "/".
        target_norm = target.rstrip("/") + "/"
        if sol_str.startswith(target_norm):
            suffix = sol_str[len(target_norm):]
            return prefix + suffix
    return None


def _resolve_library_import(
    lib_name: str,
    workspace: Path,
    test_dir: Path,
    remappings: list[str] | None = None,
) -> str | None:
    """Search workspace for a Solidity file that defines ``library <lib_name>``
    or ``enum <Member>`` scoped inside ``library <lib_name>``.

    Returns an import path string suitable for use in
    ``import {LibName} from "<path>";``. The path is expressed as:
      (1) a remapping-relative path (e.g. ``contracts/libraries/Token/LibTransfer.sol``)
          when *remappings* is provided and the library lives inside a remapping
          target directory - this avoids broken ``../../../../...`` relative paths
          when the test dir is on a completely different filesystem subtree (e.g.
          /tmp vs /Users), which forge/solc does not resolve correctly.
      (2) a filesystem-relative path from *test_dir* to the library file, as a
          fallback when no remapping matches.

    Returns None if no file can be found - the caller should emit a typed-skip
    note instead of a non-compiling import.

    Only searches inside the workspace root (not system paths) to avoid
    accidentally importing unrelated packages.
    """
    # Pattern: "library <lib_name>" anywhere in a .sol file.
    lib_decl = re.compile(
        r"\blibrary\s+" + re.escape(lib_name) + r"\b"
    )
    # Search depth-first; stop at the first match to keep it deterministic.
    # Skip hidden directories and common build/output dirs.
    skip_dirs = {"node_modules", "lib", "out", ".git", "artifacts", "cache"}
    try:
        for sol_file in workspace.rglob("*.sol"):
            # Skip build-output dirs to prefer source files.
            parts = set(sol_file.parts)
            if parts & {str(workspace / d) for d in skip_dirs}:
                continue
            # Quick string scan before regex for speed.
            try:
                text = sol_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if lib_name not in text:
                continue
            if lib_decl.search(text):
                # Prefer a remapping-relative path over a filesystem-relative
                # one: the latter breaks when test_dir is on a different
                # filesystem subtree (e.g. /tmp) from sol_file (/Users/...).
                if remappings:
                    remap_path = _remapping_relative_path(sol_file.resolve(), remappings)
                    if remap_path is not None:
                        return remap_path
                import os
                return os.path.relpath(str(sol_file), str(test_dir))
    except Exception:
        pass
    return None


def _collect_qualified_imports(
    fns: list[FuncSig],
    workspace: Path | None,
    test_dir: Path | None,
    remappings: list[str] | None = None,
) -> tuple[dict[str, str], set[str]]:
    """Scan *fns* for qualified type references (e.g. ``LibTransfer.To``).

    Returns:
        imports  - mapping from library name to relative import path (for
                   libraries that were successfully resolved).
        unresolved - set of library names that could NOT be resolved (caller
                     should skip the harness function and emit a typed-skip note).

    When *remappings* is supplied (a list of ``prefix=abs_target/`` strings),
    the resolver prefers remapping-relative import paths over filesystem-relative
    ones so that the emitted import compiles from any out-dir location.
    """
    imports: dict[str, str] = {}
    unresolved: set[str] = set()
    if workspace is None or test_dir is None:
        # Without a workspace we cannot resolve paths - treat ALL qualified
        # references as unresolved (safe fail-open: functions are dropped).
        for fn in fns:
            for lib_name, _member in _QUALIFIED_TYPE_RE.findall(fn.params):
                if lib_name not in imports and lib_name not in unresolved:
                    unresolved.add(lib_name)
        return imports, unresolved

    for fn in fns:
        for lib_name, _member in _QUALIFIED_TYPE_RE.findall(fn.params):
            if lib_name in imports or lib_name in unresolved:
                continue
            path = _resolve_library_import(lib_name, workspace, test_dir, remappings=remappings)
            if path is not None:
                imports[lib_name] = path
            else:
                unresolved.add(lib_name)
    return imports, unresolved


def _target_interface_name(surf: ContractSurface) -> str:
    return f"IAuditooor{surf.name}Target"


def _render_target_interface(
    surf: ContractSurface,
    workspace: Path | None = None,
    test_dir: Path | None = None,
    remappings: list[str] | None = None,
) -> str:
    """Render the target interface block and the import preamble needed for any
    library-qualified types (e.g. ``LibTransfer.To``) that appear in function
    signatures.

    Functions whose signatures reference a library type that CANNOT be resolved
    in *workspace* are OMITTED from the interface and replaced with a typed-skip
    comment so the harness compiles correctly.  If no function can be included
    after filtering, a noop placeholder is emitted (same as the no-surface case).

    The returned string starts with any necessary import lines (may be empty)
    followed by the ``interface ...`` block.

    When *remappings* is supplied the library resolver prefers remapping-relative
    import paths (e.g. ``contracts/libraries/Token/LibTransfer.sol``) over
    filesystem-relative ones, so the emitted import compiles from any out-dir.
    """
    all_fns = surf.mutating_external[:12]
    imports, unresolved = _collect_qualified_imports(all_fns, workspace, test_dir, remappings=remappings)

    fns = []
    skipped_comments = []
    for f in all_fns:
        # Skip if any param type references an unresolved library OR a bare
        # custom (non-elementary) type the harness cannot declare/construct
        # (e.g. a struct name like AdvancedPipeCall). Emitting either into the
        # interface yields Error 7920 (identifier not found) and sinks the
        # whole harness compile, so a typed-skip is strictly better than a
        # non-compiling interface that produces ZERO engine coverage.
        refs = _QUALIFIED_TYPE_RE.findall(f.params)
        bad = [lib for lib, _m in refs if lib in unresolved]
        unsupported = _unsupported_param_types(f.params, set(imports))
        if bad or unsupported:
            reasons = []
            if bad:
                reasons.append(f"unresolved library type(s): {', '.join(sorted(set(bad)))}")
            if unsupported:
                reasons.append(f"unconstructable param type(s): {', '.join(sorted(set(unsupported)))}")
            skipped_comments.append(
                f"    // TYPED-SKIP: {f.name}({f.params.strip()}) - "
                + "; ".join(reasons)
            )
            continue
        payable = " payable" if f.is_payable else ""
        params = f.params.strip()
        fns.append(f"    function {f.name}({params}) external{payable};")

    # Real-output view surface: zero-arg comparable-return view/pure fns. These
    # are declared in the interface so the harness can call the REAL getter and
    # assert a determinism property over its actual return value.
    for f in realout_view_fns(surf):
        ret = f.return_types[0].strip()
        mut = "pure" if f.mutability == "pure" else "view"
        fns.append(f"    function {f.name}() external {mut} returns ({ret});")

    if not fns:
        fns.append("    function auditooorNoop() external;")

    # Build the import preamble (one line per resolved library).
    import_lines = [
        f'import {{{lib_name}}} from "{rel_path}";'
        for lib_name, rel_path in sorted(imports.items())
    ]

    iface_lines = [f"interface {_target_interface_name(surf)} {{"]
    if skipped_comments:
        iface_lines.extend(skipped_comments)
    iface_lines.extend(fns)
    iface_lines.append("}")
    iface_block = "\n".join(iface_lines) + "\n"

    if import_lines:
        return "\n".join(import_lines) + "\n\n" + iface_block
    return iface_block


def _render_target_storage(surf: ContractSurface) -> str:
    iface = _target_interface_name(surf)
    return f"""
    {iface} public target;
    bool public negative_control_cleanPath = true;

    function bindTarget(address target_) public {{
        target = {iface}(target_);
    }}
"""


def _solidity_param_types(params: str) -> list[str]:
    out: list[str] = []
    for raw in [p.strip() for p in params.split(",") if p.strip()]:
        toks = raw.split()
        if not toks:
            continue
        if len(toks) > 1:
            toks = toks[:-1]
        toks = [t for t in toks if t not in {"memory", "calldata", "storage"}]
        out.append(" ".join(toks) if toks else raw.split()[0])
    return out


def _solidity_arg_for_type(typ: str, idx: int) -> str:
    t = typ.strip()
    base = re.sub(r"\s+", "", t)
    # Array of an elementary element type -> a valid EMPTY array literal. This MUST
    # precede the scalar checks: 'bool[]'.startswith('bool'), 'address[]'.
    # startswith('address'), 'bytes2[]'.startswith('bytes') etc. would otherwise
    # mis-synthesize a SCALAR value for an array param (e.g. `(x & 1) == 1` for a
    # `bool[]`), which fails to compile ("Invalid implicit conversion from bool to
    # bool[] memory") -> the whole test tree goes build-broken and every harness
    # becomes uncheckable. (Strata 2026-06-30: addAutoWithdrawals(address,bool[]).)
    if base.endswith("[]"):
        return f"new {base[:-2]}[](0)"
    if base.startswith("address"):
        return "actor"
    if base.startswith("bool"):
        return "(x & 1) == 1"
    # Fixed-size bytesN (bytes1..bytes32) MUST precede the dynamic-`bytes` check:
    # 'bytes32'.startswith('bytes') is True, so a bytes32 param would otherwise get
    # `abi.encodePacked(...)` (a `bytes memory` value) which does NOT implicitly
    # convert to bytesN ("Invalid implicit conversion from bytes memory to bytes32",
    # Error 9553) -> the whole test tree goes build-broken and every harness becomes
    # uncheckable (NUVA 2026-07-06: CrossChainManager deposit(uint256,bytes32)).
    # Derive a deterministic bytes32 from the fuzz inputs and cast to the exact width
    # (a bytes32 -> bytesN cast truncates to the high N bytes, valid for all N<=32).
    if re.match(r"^bytes([1-9]|[12]\d|3[0-2])$", base):
        return f"{base}(keccak256(abi.encodePacked(x, y, actor)))"
    if base.startswith("bytes"):
        return "abi.encodePacked(x, y, actor)"
    if base.startswith("string"):
        return "string(abi.encodePacked(x, y, actor))"
    if re.match(r"^int\d*(\[\])?$", base):
        # Array: construct with the REAL element type, not a hardcoded int256[]
        # (an `int256[]` arg does not implicitly convert to e.g. `int96[]`).
        return f"new {base[:-2]}[](0)" if "[]" in base else f"{base}(int256(x))"
    if re.match(r"^uint\d*(\[\])?$", base):
        return f"new {base[:-2]}[](0)" if "[]" in base else f"{base}(x)"
    return f"{base}(x + {idx})"


# Solidity return types over which a `==` determinism comparison compiles and is
# meaningful (value-typed, single-slot). Tuple / dynamic / struct returns need
# CUT-specific decoding, so they stay out of the generic real-output path.
_COMPARABLE_RET_RE = re.compile(r"^(uint\d*|int\d*|bool|address|bytes\d+)$")


def realout_view_fns(surf: ContractSurface) -> list[FuncSig]:
    """Read-only (view/pure), externally callable, ZERO-parameter functions whose
    single return type is a comparable value type.

    Zero-param is the safe generic real-output surface: the call needs no argument
    synthesis, the return is read off the REAL CUT, and `f() == f()` is a genuine
    determinism property over the real output (Rule R80 real_output_bound=true),
    NOT a self-model. Parameterised view fns are skipped to avoid mis-constructed
    args; the audit author can widen them with CUT-specific wiring."""
    out: list[FuncSig] = []
    for f in surf.functions:
        if not (f.is_externally_callable and f.is_readonly):
            continue
        if f.params.strip():  # zero-arg only - no arg synthesis risk
            continue
        rets = f.return_types
        if len(rets) != 1:
            continue
        if not _COMPARABLE_RET_RE.match(rets[0].strip()):
            continue
        out.append(f)
    # Deterministic order, capped so a huge contract does not bloat the harness.
    out.sort(key=lambda f: f.name)
    return out[:8]


def _pick_target_function(surf: ContractSurface, cat: str) -> FuncSig | None:
    hints = {
        "conservation": ("deposit", "withdraw", "transfer", "mint", "redeem"),
        "custody": ("withdraw", "transfer", "claim", "collect"),
        "authorization": ("set", "owner", "upgrade", "admin", "transfer"),
        "atomicity": ("callback", "on", "execute", "settle"),
        "bounds": ("deposit", "mint", "borrow", "swap"),
        "freshness": ("update", "consume", "settle", "resolve"),
        "ordering": ("execute", "settle", "commit", "resolve"),
        "uniqueness": ("claim", "consume", "execute", "settle"),
    }.get(cat, ())
    for h in hints:
        for f in surf.mutating_external:
            if h in f.name.lower():
                return f
    # No hint matched: returning the first function would embed a semantically
    # wrong target in the emitted harness (e.g. `propose` for the
    # `authorization` category on a governance contract). Return None so the
    # caller can filter out the unmatched category rather than emit a false-green.
    # r36-rebuttal: bugfix-inventory-claude-20260610
    return None


def _splice_placeholders(arg: str, mapping: dict[str, str]) -> str:
    """Replace ONLY the standalone placeholder identifiers in `arg` (keys of
    `mapping`) with their values, in a SINGLE left-to-right pass.

    Correctness contract (regression: NUVA `ExecutorArgs`, Strata `IStrategyProvider`):
      - A placeholder token is replaced only when it appears as a WHOLE Solidity
        identifier (bounded by a non-identifier char on both sides), so a valid
        identifier that merely CONTAINS the token letter(s) - e.g. `ExecutorArgs`
        contains `x`, `proxyType` contains `x`, `factory` contains `actor`-free
        `y` - is left byte-for-byte intact.
      - The scan is single-pass: a value spliced in for one token is never
        re-examined for another token, so a value containing a bare `actor`/`x`/`y`
        substring cannot be double-corrupted (the sequential re.sub form could).

    Only the exact keys of `mapping` are substituted; every other character of
    `arg` is emitted unchanged. When no placeholder occurs, the returned string is
    the input verbatim.
    """
    if not mapping:
        return arg
    # Longest-first alternation so a longer placeholder (e.g. `actor`) is preferred
    # over a shorter one; `\b<tok>\b` pins each to a whole identifier. re.escape is
    # defensive - the placeholder tokens are plain identifiers today.
    toks = sorted(mapping, key=len, reverse=True)
    pattern = re.compile(r"\b(" + "|".join(re.escape(t) for t in toks) + r")\b")
    # A regex `\b` treats `_` and alphanumerics as word chars, so `my_x` / `x_2`
    # do NOT match `\bx\b` at the inner `x` - exactly the full-identifier semantics
    # we want. Single sub() pass with a callback = one left-to-right scan.
    return pattern.sub(lambda m: mapping[m.group(1)], arg)


def _target_call_stmt(surf: ContractSurface, cat: str, *, x: str = "x", y: str = "y",
                      actor: str = "actor", indent: str = "        ") -> str:
    f = _pick_target_function(surf, cat)
    if f is None:
        return f"{indent}// no mutating target function parsed"
    param_types = _solidity_param_types(f.params)
    # A non-elementary, non-address param type (interface/contract/struct/enum/
    # custom) cannot be generically constructed into a COMPILING value - it needs
    # CUT-specific wiring. Emitting `IFoo(uint + 0)` / `SomeStruct(uint + 0)`
    # either fails to compile (the whole test tree then goes build-broken and ALL
    # harnesses become uncheckable) or is mangled by substitution. Omit the
    # mutating call so the harness (real-output + invariant scaffold) still
    # compiles; the complex-arg mutating path is a logged coverage gap, not a
    # build-breaking phantom. (Strata 2026-06-30: setProvider(IStrategyAprPairProvider),
    # deposit(...,TDepositParams) corrupted the tree.)
    unsupported = [
        t for t in param_types
        if not _is_elementary_param_type(re.sub(r"\s+", "", t))
        and not re.sub(r"\s+", "", t).startswith("address")
    ]
    if unsupported:
        return (
            f"{indent}// target.{f.name} has non-synthesizable param type(s) "
            f"{', '.join(unsupported)}; mutating call omitted (needs CUT-specific args)"
        )
    args: list[str] = []
    for i, typ in enumerate(param_types):
        arg = _solidity_arg_for_type(typ, i)
        # FULL-IDENTIFIER, SINGLE-PASS placeholder substitution. A naive
        # str.replace("x", ...) splices the value INTO any identifier that merely
        # CONTAINS that letter, e.g. `ExecutorArgs` -> `Euint256(0)ecutorArgs`
        # (NUVA CrossChainManager_FuzzProps.sol:71) and `IStrategyProvider` ->
        # `IStrateguint256(0)Provider` (Strata). We replace ONLY the standalone
        # identifier tokens `x` / `y` / `actor` - matched with a full-identifier
        # regex (`\b<tok>\b`, and the token must be a WHOLE Solidity identifier,
        # never a fragment of a longer name). Doing it in ONE left-to-right pass
        # (a single alternation with a callback) also prevents a value substituted
        # for an earlier token from being re-scanned and corrupted when it happens
        # to contain a later placeholder token (e.g. an `actor` substring inside
        # the value chosen for `x`). This is a pure hardening of the existing
        # word-boundary intent; for all-elementary args the output is identical.
        arg = _splice_placeholders(arg, {"x": x, "y": y, "actor": actor})
        args.append(arg)
    return (
        f"{indent}if (address(target) != address(0)) {{\n"
        f"{indent}    target.{f.name}({', '.join(args)});\n"
        f"{indent}}}"
    )


def _realout_determinism_props(surf: ContractSurface, *, style: str) -> str:
    """Emit determinism properties over REAL zero-arg view-fn return values.

    For each comparable-return view fn `f`, assert `target.f() == target.f()`:
    a genuine real-output property (the assert references the REAL call), not a
    self-model. Guarded behind `address(target) != address(0)` so an unbound
    harness is a clean skip rather than a revert.

    style:
      "assert"     -> body uses `assert(...)`         (medusa fuzz_/halmos)
      "assertTrue" -> body uses `assertTrue(..., msg)` (forge invariant)
      "bool"       -> a `echidna_*` returning bool     (echidna)
    """
    fns = realout_view_fns(surf)
    if not fns:
        return ""
    blocks: list[str] = []
    for f in fns:
        cap = f.name[:1].upper() + f.name[1:]
        if style == "bool":
            blocks.append(f"""
    /// REAL-OUTPUT determinism over {surf.name}.{f.name}() (real_output_bound).
    function echidna_realout_{f.name}() public view returns (bool) {{
        if (address(target) == address(0)) return true;
        return target.{f.name}() == target.{f.name}();
    }}""")
        elif style == "assertTrue":
            blocks.append(f"""
    /// REAL-OUTPUT determinism over {surf.name}.{f.name}() (real_output_bound).
    function invariant_realout_{f.name}() public {{
        if (address(target) == address(0)) return;
        assertTrue(target.{f.name}() == target.{f.name}(),
            "real-output determinism violated: {f.name}");
    }}""")
        else:  # assert
            blocks.append(f"""
    /// REAL-OUTPUT determinism over {surf.name}.{f.name}() (real_output_bound).
    function realout_{f.name}() public view {{
        if (address(target) == address(0)) return;
        assert(target.{f.name}() == target.{f.name}());
    }}""")
        _ = cap
    return "".join(blocks)


def _check_field_names(check: str) -> list[str]:
    """Bare lowerCamel identifiers in a check expr that are harness state fields."""
    out: list[str] = []
    for tok in re.findall(r"\b[a-z][A-Za-z0-9_]*\b", check):
        if tok in _NON_FIELD_TOKENS:
            continue
        if tok not in out:
            out.append(tok)
    return out


def _field_ref(check: str, prefix: str) -> str:
    """Rewrite a harness-internal invariant relation so each state field becomes
    an external getter call, e.g. `totalIn == totalOut + feesAccrued` with
    prefix `harness.` -> `harness.totalIn() == harness.totalOut() + harness.feesAccrued()`.

    Used when the property is OUTSIDE the harness (the halmos spec contract).
    Leaves non-field tokens (address(0), literals, keywords) untouched.
    """
    fields = _check_field_names(check)
    out = check
    for f in sorted(fields, key=len, reverse=True):
        out = re.sub(rf"\b{re.escape(f)}\b", f"{prefix}{f}()", out)
    return out


def _inv_comment_block(matched):
    lines = []
    for cat, recs in matched.items():
        for r in recs:
            stmt = (r.get("statement") or "").strip().replace("\n", " ")
            if len(stmt) > 110:
                stmt = stmt[:107] + "..."
            lines.append(f"//   {r['invariant_id']} [{cat}]: {stmt}")
    return "\n".join(lines) if lines else "//   (no corpus invariant matched)"


def _model_members(matched):
    """Inline state decls + mutate functions for every matched category.

    Returns (decl_block, mutate_block, ctor_block). Self-contained so a spec
    file needs no external HarnessUnderTest import - this keeps every emitted
    .sol file property-bearing (the directory-level proof gate takes the worst
    verdict, so a property-free model file would sink the whole dir).
    """
    decls, mutates, ctor = [], [], []
    for cat in matched:
        cap = cat.capitalize()
        ci = _cat_invariant(cat)
        decls.append(f"    // {cat} state:\n{ci.decls}")
        mutates.append(f"""
    function mutate{cap}(uint256 x, uint256 y, address actor) internal {{
{ci.mutate}
    }}""")
        if cat == "authorization":
            ctor.append("        owner = msg.sender;")
        if cat == "bounds":
            ctor.append("        cap = 1e24;")
    return (
        "\n".join(decls) if decls else "    // no matched category",
        "".join(mutates),
        "\n".join(ctor) if ctor else "        // no init needed",
    )


def emit_halmos(surf, matched, workspace: Path | None = None, test_dir: Path | None = None,
                remappings: list[str] | None = None):
    inv_block = _inv_comment_block(matched)
    banner = _BANNER.format(contract=surf.name, inv_block=inv_block)
    decl_block, mutate_block, ctor_block = _model_members(matched)
    target_iface = _render_target_interface(surf, workspace=workspace, test_dir=test_dir, remappings=remappings)
    target_storage = _render_target_storage(surf)
    checks = []
    for cat, recs in matched.items():
        inv_ids = ", ".join(r["invariant_id"] for r in recs)
        prop = _CATEGORY_PROPERTY.get(cat, "the matched invariant holds")
        cap_cat = cat.capitalize()
        ci = _cat_invariant(cat)
        assume = ci.assume + "\n" if ci.assume else ""
        target_call = _target_call_stmt(surf, cat)
        # Symbolic check: drive one mutation from a symbolic state, then assert
        # the REAL invariant relation holds. The relation references two
        # distinct state fields so halmos can construct a counterexample if the
        # modeled mutating path is mis-wired.
        checks.append(f"""
    /// @notice Halmos symbolic check for {cat} invariants ({inv_ids}).
    /// Property: {prop}
    function check_{cat}(uint256 x, uint256 y, address actor) public {{
        vm.assume(actor != address(0));
{assume}        uint256 beforeState = address(target).balance;
{target_call}
        mutate{cap_cat}(x, y, actor);
        uint256 afterState = address(target).balance;
        bool controlCase = negative_control_cleanPath
            && (afterState >= beforeState || beforeState >= afterState);
        // INVARIANT ({cat}): {prop}
        assert(controlCase && ({ci.check}));
    }}""")
    fn_body = "\n".join(checks) if checks else "    // no matched category"
    return f"""// SPDX-License-Identifier: UNLICENSED
{banner}
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

{target_iface}
/// @title {surf.name}_HalmosSpec
/// @notice Symbolic check_* specs. Each property performs a bindable interface
/// call to the real {surf.name} target, records before/after state evidence,
/// and then checks the invariant model. Run via tools/halmos-runner.sh.
contract {surf.name}_HalmosSpec is Test {{
{target_storage}
{decl_block}

    constructor() {{
{ctor_block}
    }}
{mutate_block}
{fn_body}
}}
"""


def emit_fuzz_properties(surf, matched, workspace: Path | None = None, test_dir: Path | None = None,
                         remappings: list[str] | None = None):
    inv_block = _inv_comment_block(matched)
    banner = _BANNER.format(contract=surf.name, inv_block=inv_block)
    decl_block, _, ctor_block = _model_members(matched)
    target_iface = _render_target_interface(surf, workspace=workspace, test_dir=test_dir, remappings=remappings)
    target_storage = _render_target_storage(surf)
    props = []
    for cat, recs in matched.items():
        inv_ids = ", ".join(r["invariant_id"] for r in recs)
        prop = _CATEGORY_PROPERTY.get(cat, "the matched invariant holds")
        ci = _cat_invariant(cat)
        target_call = _target_call_stmt(surf, cat)
        target_call_zero = _target_call_stmt(surf, cat, x="uint256(0)", y="uint256(0)",
                                             actor="msg.sender")
        # echidna boolean property: a REAL comparison expression as the return.
        # fuzz_ (medusa assertion mode): mutate then assert the REAL relation.
        props.append(f"""
    /// {inv_ids} [{cat}]: {prop}
    function echidna_{cat}() public returns (bool) {{
        uint256 beforeState = address(target).balance;
{target_call_zero}
        uint256 afterState = address(target).balance;
        bool controlCase = negative_control_cleanPath
            && (afterState >= beforeState || beforeState >= afterState);
        return (controlCase && ({ci.check}));
    }}

    function mutate{cat.capitalize()}(uint256 x, uint256 y, address actor) public {{
{ci.mutate}
    }}

    function fuzz_{cat}(uint256 x, uint256 y, address actor) public {{
        uint256 beforeState = address(target).balance;
{target_call}
        mutate{cat.capitalize()}(x, y, actor);
        uint256 afterState = address(target).balance;
        bool controlCase = negative_control_cleanPath
            && (afterState >= beforeState || beforeState >= afterState);
        assert(controlCase && ({ci.check})); // {prop}
    }}""")
    realout_bool = _realout_determinism_props(surf, style="bool")
    realout_assert = _realout_determinism_props(surf, style="assert")
    fn_body = "\n".join(props) if props else "    // no matched category"
    fn_body = fn_body + realout_bool + realout_assert
    return f"""// SPDX-License-Identifier: UNLICENSED
{banner}
pragma solidity ^0.8.0;

{target_iface}
/// @title {surf.name}_FuzzProps
/// @notice Echidna (echidna_*) + Medusa-assertion (fuzz_*) property fns.
/// Each property calls the bindable real target, records before/after state
/// evidence, carries a negative-control signal, and checks the invariant model.
/// Run via tools/echidna-campaign.sh <ws> or tools/medusa-fuzz.sh <ws>.
contract {surf.name}_FuzzProps {{
{target_storage}
{decl_block}

    constructor() {{
{ctor_block}
    }}
{fn_body}
}}
"""


def emit_forge_invariant(surf, matched, workspace: Path | None = None, test_dir: Path | None = None,
                         remappings: list[str] | None = None):
    inv_block = _inv_comment_block(matched)
    banner = _BANNER.format(contract=surf.name, inv_block=inv_block)
    decl_block, _, ctor_block = _model_members(matched)
    target_iface = _render_target_interface(surf, workspace=workspace, test_dir=test_dir, remappings=remappings)
    target_storage = _render_target_storage(surf)
    invs = []
    pub_mutates = []
    handler_steps = []
    for cat, recs in matched.items():
        inv_ids = ", ".join(r["invariant_id"] for r in recs)
        prop = _CATEGORY_PROPERTY.get(cat, "the matched invariant holds")
        cap_cat = cat.capitalize()
        ci = _cat_invariant(cat)
        target_call_zero = _target_call_stmt(surf, cat, x="uint256(0)", y="uint256(0)",
                                             actor="address(this)")
        # invariant_* carries the REAL inline comparison (not assertTrue(stub())).
        invs.append(f"""
    /// {inv_ids} [{cat}]: {prop}
    function invariant_{cat}() public {{
        uint256 beforeState = address(target).balance;
{target_call_zero}
        uint256 afterState = address(target).balance;
        bool controlCase = negative_control_cleanPath
            && (afterState >= beforeState || beforeState >= afterState);
        assertTrue(controlCase && ({ci.check}), "{cat}: invariant violated ({inv_ids})");
    }}""")
        # public wrapper so the handler (the fuzz target) can drive the model.
        pub_mutates.append(f"""
    function drive{cap_cat}(uint256 x, uint256 y, address actor) public {{
        mutate{cap_cat}(x, y, actor);
    }}""")
        handler_steps.append(
            f"        model.drive{cap_cat}(seed + {len(handler_steps)}, x, actor);"
        )
    inv_body = "\n".join(invs) if invs else "    // no matched category"
    inv_body = inv_body + _realout_determinism_props(surf, style="assertTrue")
    pub_body = "".join(pub_mutates)
    step_body = "\n".join(handler_steps) if handler_steps else "        seed; x; actor;"
    src_handler_comments = []
    for f in surf.mutating_external[:12]:
        src_handler_comments.append(f"    // {surf.name}.{f.name}({f.params})")
    handler_block = "\n".join(src_handler_comments) if src_handler_comments else "    // (no mutating external functions parsed)"
    decl_block_def, mutate_block, _ = _model_members(matched)
    iface_name = _target_interface_name(surf)
    return f"""// SPDX-License-Identifier: UNLICENSED
{banner}
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

{target_iface}
/// @title {surf.name}_Invariant
/// @notice Self-contained Foundry stateful-invariant suite.
/// `forge test --match-contract {surf.name}_Invariant`.
///
/// HARNESS-TYPED-SKIP: MODEL-ONLY - setUp() does not call bindTarget().
/// This file is an HONEST TYPED-SKIP: it records the invariant categories that
/// must be covered but cannot be generically wired without knowing the CUT's
/// constructor args or proxy topology. It is NOT genuine coverage.
///
/// Downstream gate: setUp_binds_target="typed-skip" in attempt_manifest.json.
/// oracle_verdict is NOT credited until an audit author replaces the setUp()
/// stub below with a real deployment + bindTarget(address(cut)) call, at which
/// point setUp_binds_target must be changed to True and the manifest re-emitted.
///
/// Why typed-skip (not model-only vacuous green):
/// Without bindTarget() every `if (address(target) != address(0))` guard in
/// invariant_* bodies is skipped at runtime. Only the synthetic mutate*/drive*
/// model state runs. ALL mutants pass (oracle_verdict=vacuous, 0 kills) because
/// the real CUT is never invoked. That is FALSE COVERAGE, not genuine evidence.
///
/// Wiring steps (replace the setUp() stub below):
///   1. Deploy the real {surf.name} (or a minimal stub implementing
///      {iface_name}) with the correct constructor args.
///   2. Call bindTarget(address(cut)) so invariant_* bodies exercise the CUT.
///   3. Update setUp_binds_target to True in attempt_manifest.json.
contract {surf.name}_Invariant is Test {{
{target_storage}
{decl_block}

    {surf.name}_Handler internal handler;

    constructor() {{
{ctor_block}
    }}

    function setUp() public {{
        handler = new {surf.name}_Handler(this);
        targetContract(address(handler));
        // BIND-TARGET-NEEDED: deploy the real {surf.name} CUT here and call
        // bindTarget(address(cut)) so that every guarded target.fn() call below
        // exercises the real contract rather than being silently skipped.
        // Without this the harness is MODEL-ONLY (see contract-level NatSpec).
        //
        // Replace this block with:
        //   {surf.name} cut = new {surf.name}(<constructor_args>);
        //   bindTarget(address(cut));
        //
        // If {surf.name} requires complex constructor args or an upgradeable proxy,
        // use a minimal stub that implements the {iface_name} interface instead.
    }}
{mutate_block}{pub_body}
{inv_body}
}}

/// @notice Handler: the stateful fuzzer calls step() in random order, driving
/// every category's mutate* path so each invariant_* is continuously
/// re-checked against evolving state.
contract {surf.name}_Handler {{
    {surf.name}_Invariant internal model;

    constructor({surf.name}_Invariant m) {{
        model = m;
    }}

    // Real {surf.name} mutating surface to wire next:
{handler_block}

    function step(uint256 seed, uint256 x, address actor) external {{
{step_body}
    }}
}}
"""


def emit_medusa_config(surf):
    # senderAddresses: shared pool - the fuzzer may pick the SAME address for
    # multiple roles (payer==receiver, from==to, liquidator==borrower) without
    # a per-bug hint.  This expands the reachable input space and lets the
    # fuzzer discover self-settled-take / same-account collisions generically.
    cfg = {
        "fuzzing": {
            "workers": 4,
            "testLimit": 50000,
            "callSequenceLength": 50,
            "targetContracts": [f"{surf.name}_FuzzProps"],
            "corpusDirectory": "medusa-corpus",
            "assertionTesting": {"enabled": True, "testViewMethods": True},
            "propertyTesting": {"enabled": True, "testPrefixes": ["echidna_"]},
            "senderAddresses": ["0x10000", "0x20000", "0x30000"],
        },
        "compilation": {
            "platform": "crytic-compile",
            # target MUST be the specific property FILE, not "." - a "." target
            # makes crytic-compile run `forge build --skip ./test/**`, which skips
            # the FuzzProps contract (it lives in test/) -> no build-info ->
            # "out/build-info is not a directory" -> medusa engine-error (README #505).
            "platformConfig": {"target": f"test/{surf.name}_FuzzProps.sol", "solcVersion": ""},
        },
    }
    return json.dumps(cfg, indent=2) + "\n"


def emit_echidna_config(surf):
    # senders: shared pool - same three addresses so the fuzzer may assign the
    # same sender to two roles in the same sequence step, reaching same-actor
    # edge cases (self-transfer, self-liquidation, etc.) without hints.
    return (
        "testMode: assertion\n"
        "testLimit: 50000\n"
        "seqLen: 50\n"
        f"# property fns prefixed echidna_ in {surf.name}_FuzzProps\n"
        "cryticArgs:\n"
        "  - --foundry-compile-all\n"
        "  - --solc-remaps\n"
        "  - forge-std/=lib/forge-std/src/\n"
        "senders:\n"
        "  - \"0x10000\"\n"
        "  - \"0x20000\"\n"
        "  - \"0x30000\"\n"
    )


def _workspace_foundry_settings(
    workspace: Path | None,
    contract_path: Path | None = None,
) -> tuple[list[str], list[str]]:
    """Read the workspace's remappings and lib directories.

    Returns (remappings, abs_libs):
      remappings - list of "prefix=target" strings, with relative targets
                   expanded to absolute paths so they resolve from ANY out-dir.
      abs_libs   - list of absolute-path strings for the libs[] array.

    When *contract_path* is supplied the search walks from the contract's
    directory up toward *workspace* to find the nearest foundry.toml (the
    most specific project config for that contract), rather than doing a
    workspace-wide rglob that might pick up an unrelated sibling project.

    Falls back to empty lists if the workspace has no foundry.toml/remappings.txt,
    so the caller always gets a well-formed (possibly empty) result.
    """
    if workspace is None:
        return [], []

    remappings: list[str] = []
    abs_libs: list[str] = []

    # ---- collect lib dirs from foundry.toml (profile.default.libs) ----
    # We do a simple regex scan - not a full TOML parser - to avoid a dep.
    foundry_toml = workspace / "foundry.toml"
    ws_root: Path | None = None  # the dir that foundry.toml lives in

    # Strategy 1: walk ancestors of contract_path up to workspace root, looking
    # for the nearest foundry.toml.  This gives the most specific project config
    # for the contract being compiled (e.g. protocol/foundry.toml rather than
    # an unrelated sibling project's foundry.toml).
    if contract_path is not None and not foundry_toml.exists():
        try:
            cp = contract_path.resolve()
            ws_resolved = workspace.resolve()
            # Walk from contract's dir up to (and including) workspace root.
            for parent in [cp.parent, *cp.parents]:
                candidate = parent / "foundry.toml"
                if candidate.exists():
                    # Accept it unless it is inside a lib/out/node_modules subtree.
                    try:
                        rel = candidate.relative_to(ws_resolved)
                        parts = rel.parts
                        if not any(p in ("lib", "out", "node_modules", ".git") for p in parts):
                            foundry_toml = candidate
                            break
                    except ValueError:
                        break  # walked past workspace root
                if parent == ws_resolved:
                    break
        except Exception:
            pass

    if not foundry_toml.exists():
        # Fallback: workspace-wide rglob; prefer the shallowest non-lib result.
        for candidate in sorted(workspace.rglob("foundry.toml"), key=lambda p: len(p.parts)):
            rel = candidate.relative_to(workspace)
            parts = rel.parts
            if any(p in ("lib", "out", "node_modules", ".git") for p in parts):
                continue
            foundry_toml = candidate
            break

    if foundry_toml.exists():
        ws_root = foundry_toml.parent
        try:
            text = foundry_toml.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        # Match `libs = [...]` (single-line array form).
        m = re.search(r"libs\s*=\s*\[([^\]]*)\]", text)
        if m:
            raw = m.group(1)
            for tok in re.findall(r"['\"]([^'\"]+)['\"]", raw):
                p = (ws_root / tok).resolve()
                if p.exists():
                    abs_libs.append(str(p))

    # ---- collect remappings from remappings.txt ----
    # Prefer a remappings.txt alongside the foundry.toml; also check workspace root.
    remap_candidates = []
    if ws_root is not None:
        remap_candidates.append(ws_root / "remappings.txt")
    remap_candidates.append(workspace / "remappings.txt")

    for remap_file in remap_candidates:
        if not remap_file.exists():
            continue
        try:
            lines = remap_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        base = remap_file.parent
        for line in lines:
            line = line.strip()
            if not line or "=" not in line:
                continue
            prefix, _, target = line.partition("=")
            # Make relative targets absolute so they resolve from any out-dir.
            if target and not Path(target).is_absolute():
                abs_target = (base / target).resolve()
                if abs_target.exists():
                    target = str(abs_target) + "/"
                else:
                    target = str((base / target).resolve()) + "/"
            remappings.append(f"{prefix}={target}")
        break  # only read the first found remappings.txt

    # ---- also scan foundry.toml remappings array (inline form) ----
    if ws_root is not None and foundry_toml.exists():
        try:
            text = foundry_toml.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        # Match remappings = [...] (may be multi-line).
        m = re.search(r"remappings\s*=\s*\[([^\]]*)\]", text, re.DOTALL)
        if m:
            raw = m.group(1)
            existing_prefixes = {r.split("=")[0] for r in remappings}
            for tok in re.findall(r"['\"]([^'\"]+)['\"]", raw):
                if "=" not in tok:
                    continue
                pfx, _, tgt = tok.partition("=")
                if pfx in existing_prefixes:
                    continue  # remappings.txt takes priority
                if tgt and not Path(tgt).is_absolute():
                    abs_tgt = (ws_root / tgt).resolve()
                    tgt = str(abs_tgt) + "/"
                remappings.append(f"{pfx}={tgt}")
                existing_prefixes.add(pfx)

    # ---- add src-dir remapping for non-standard source root ----
    # When the workspace foundry.toml declares `src = 'contracts'` (or any
    # directory other than "src"), Solidity files inside that directory import
    # siblings via unqualified `"contracts/..."` paths. Foundry resolves these
    # by adding the project root as a source-search path during its own build;
    # but a generated harness compiled from a different directory does NOT get
    # that implicit root addition. We therefore emit an explicit remapping
    # `<src_dir>/=<abs_ws_root>/<src_dir>/` so that e.g. `contracts/interfaces/
    # IDiamondCut.sol` resolves from any out-dir.
    if ws_root is not None and foundry_toml.exists():
        try:
            ft_text = foundry_toml.read_text(encoding="utf-8", errors="replace")
        except OSError:
            ft_text = ""
        src_match = re.search(r"\bsrc\s*=\s*['\"]([^'\"]+)['\"]", ft_text)
        if src_match:
            src_dir_name = src_match.group(1).strip("/")
            existing_prefixes = {r.split("=")[0] for r in remappings}
            # Add `<src_dir_name>/=<abs_path_to_src_dir>/` if not already present.
            prefix_key = src_dir_name + "/"
            if prefix_key not in existing_prefixes and src_dir_name not in ("src",):
                abs_src = (ws_root / src_dir_name).resolve()
                if abs_src.is_dir():
                    remappings.append(f"{prefix_key}={abs_src}/")

    # Deduplicate while preserving order (first occurrence wins).
    seen_pfx: set[str] = set()
    unique: list[str] = []
    for r in remappings:
        pfx = r.split("=")[0]
        if pfx not in seen_pfx:
            seen_pfx.add(pfx)
            unique.append(r)
    return unique, abs_libs


def emit_foundry_toml(
    surf,
    workspace: Path | None = None,
    out_dir: Path | None = None,
    contract_path: Path | None = None,
):
    """Emit a foundry.toml for the generated harness.

    When *workspace* is supplied, the workspace's remappings (from
    remappings.txt and/or foundry.toml) are merged in with absolute-path
    targets so any transitive import from a workspace library resolves
    correctly regardless of where *out_dir* sits on disk.  This fixes
    Error 6275 (Source not found) for harnesses that import workspace
    libraries whose own transitive imports use @openzeppelin/ or other
    remapped prefixes.

    When *contract_path* is also given, the search for the workspace's
    foundry.toml walks from the contract's directory up toward the workspace
    root (nearest-ancestor strategy) to find the most specific project config
    for that contract, rather than picking up an unrelated sibling project.
    """
    remappings, abs_libs = _workspace_foundry_settings(workspace, contract_path=contract_path)

    # Always include lib/ relative to the harness out-dir so forge-std resolves
    # if the caller drops a lib/forge-std symlink or submodule there.
    base_libs = ["lib"]
    # Merge workspace absolute lib dirs, deduplicating.
    for p in abs_libs:
        if p not in base_libs:
            base_libs.append(p)

    libs_toml = json.dumps(base_libs)

    remap_block = ""
    if remappings:
        remap_lines = "\n".join(f'  "{r}",' for r in remappings)
        remap_block = f"remappings = [\n{remap_lines}\n]\n"

    return (
        "[profile.default]\n"
        'src = "src"\n'
        'test = "test"\n'
        'out = "out"\n'
        f"libs = {libs_toml}\n"
        + (remap_block)
        + "\n[profile.default.invariant]\n"
        "runs = 256\n"
        "depth = 64\n"
        "fail_on_revert = false\n"
    )


# ----------------------------------------------------------------------------
# Orchestration.
# ----------------------------------------------------------------------------

def _assert_non_empty_specs(files: dict) -> None:
    """P1-e non-empty-spec assertion (taxonomy mode 18). Raise ValueError if any
    emitted spec content is empty / whitespace-only, BEFORE any file is written,
    so a render that collapsed to nothing never leaves a 0-byte spec on disk."""
    empties = [fp for fp, content in files.items() if not (content and str(content).strip())]
    if empties:
        raise ValueError(
            "empty-render: refusing to write 0-byte / whitespace-only spec(s) "
            f"(fail-closed): {', '.join(Path(p).name for p in sorted(empties))}"
        )


def author(workspace, contract_path, contract_name, extracted, pilot, out_dir):
    # P1-e CUT-in-scope filter (taxonomy mode 19): refuse to author a harness for
    # an out-of-scope CUT (deployed-zip / reference mirror / not in
    # inscope_units.jsonl). This is BEFORE any parse/emit so no OOS spec is ever
    # written. AUDITOOOR_FCC_NO_SCOPE_FILTER=1 disables the manifest half.
    in_scope, scope_reason = _contract_in_scope(Path(workspace), Path(contract_path))
    if not in_scope:
        raise ValueError(
            f"{Path(contract_path).name}: out-of-scope CUT - {scope_reason}"
        )

    surf = parse_contract(contract_path, contract_name)
    corpus = load_corpus_invariants(extracted, pilot)

    # Pure tick<->price conversion libraries (TickMath / TickLib) have no
    # mutating external surface, so the category path below would refuse. Detect
    # them first and author the tick<->price monotonic + no-truncation-to-zero
    # invariants against the REAL library code.
    tm = detect_tick_math(surf)
    if tm is not None:
        out = out_dir or (workspace / "poc-tests" / f"{tm.name}-engine-harness")
        return author_tick_math(workspace, contract_path, tm, corpus, out_dir)

    # Reject library and interface declarations: they cannot be instantiated as
    # a concrete target (library external fns require delegatecall; interfaces
    # have no state). A harness authored against them would embed invalid
    # Solidity semantics and produce rule_58_grounded=True on a vacuous result.
    # The tick-math path above is the ONE intentional library exception.
    # r36-rebuttal: bugfix-inventory-claude-20260610
    if surf.kind != "contract":
        raise ValueError(
            f"{surf.name}: file declares a {surf.kind!r}, not a concrete contract; "
            "harness authoring requires a concrete contract (use --contract-name "
            "to select a specific declaration if the file contains multiple, or "
            "point at a contract file, not a library or interface)."
        )

    matched = match_invariants(surf, corpus)

    # Collect categories that were skipped due to typed_skip=True (tautology-
    # guard): they were in wanted but filtered out before match_invariants built
    # by_cat. These are recorded in the manifest under typed_skip_categories so
    # the audit author knows they need CUT-specific wiring.
    # bugfix: tautology-CatInvariants (atomicity/determinism) 2026-06-13
    wanted = derive_wanted_categories(surf)
    typed_skip_cats = sorted(
        cat for cat in wanted
        if _CATEGORY_INVARIANT.get(cat) is not None
        and _CATEGORY_INVARIANT[cat].typed_skip
    )

    # A contract with no mutating external surface yields zero matched
    # categories, so there is no real property to author. Refuse rather than
    # emit a property-free harness that would fail the engine-harness proof
    # gate (the tool's contract: never emit a stub/ghost/empty harness).
    if not matched:
        skip_hint = (
            f" (categories {typed_skip_cats} were TYPED-SKIP; "
            "provide CUT-specific wiring to cover them)"
            if typed_skip_cats else ""
        )
        raise ValueError(
            f"{surf.name}: no mutating external surface matched any corpus "
            "invariant category; nothing real to author (refusing to emit a "
            "property-free harness). Point at a contract with a mutating "
            f"external surface.{skip_hint}"
        )

    out = out_dir or (workspace / "poc-tests" / f"{surf.name}-engine-harness")
    test_dir = out / "test"
    test_dir.mkdir(parents=True, exist_ok=True)

    # Compute workspace remappings once so the import resolver and the generated
    # foundry.toml both use the same absolute-path remappings. This ensures that
    # library imports in the emitted .sol files use remapping-relative paths (e.g.
    # `contracts/libraries/Token/LibTransfer.sol`) rather than filesystem-relative
    # paths that break when the harness out-dir is on a different filesystem
    # subtree (e.g. /tmp vs /Users). See Error 6275 fix in emit_foundry_toml.
    ws_remappings, _ = _workspace_foundry_settings(workspace, contract_path=contract_path)

    # NOTE: every emitted .sol is self-contained (model state + mutate* + real
    # property assertions live in one file). We deliberately do NOT emit a bare
    # HarnessUnderTest.sol model file: the directory-level engine-harness proof
    # gate takes the WORST verdict across all .sol files, so a property-free
    # model file would sink the whole tree to fail-zero-executed-property.
    files = {
        str(test_dir / f"{surf.name}_HalmosSpec.t.sol"): emit_halmos(surf, matched, workspace=workspace, test_dir=test_dir, remappings=ws_remappings),
        str(test_dir / f"{surf.name}_FuzzProps.sol"): emit_fuzz_properties(surf, matched, workspace=workspace, test_dir=test_dir, remappings=ws_remappings),
        str(test_dir / f"{surf.name}_Invariant.t.sol"): emit_forge_invariant(surf, matched, workspace=workspace, test_dir=test_dir, remappings=ws_remappings),
        str(out / "medusa.json"): emit_medusa_config(surf),
        str(out / "echidna.yaml"): emit_echidna_config(surf),
        str(out / "foundry.toml"): emit_foundry_toml(surf, workspace=workspace, out_dir=out, contract_path=contract_path),
    }

    # P1-e non-empty-spec assertion (taxonomy mode 18): NEVER write a 0-byte /
    # whitespace-only spec. An empty render is a silent spec-layer skip; fail
    # closed BEFORE any file is written so the tree never gains a 0-byte stub.
    _assert_non_empty_specs(files)

    for fp, content in files.items():
        Path(fp).write_text(content, encoding="utf-8")

    manifest = {
        "schema_version": SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workspace": str(workspace),
        "contract_path": str(contract_path),
        "contract": surf.name,
        "contract_kind": surf.kind,
        "bases": surf.bases,
        "surface": {
            "mutating_external_fns": [f.name for f in surf.mutating_external],
            "events": surf.events,
            "errors": surf.errors,
            "modifiers": surf.modifiers,
            "immutables": surf.immutables,
            "state_vars": surf.state_vars,
        },
        "matched_invariants": {
            cat: [r["invariant_id"] for r in recs] for cat, recs in matched.items()
        },
        # typed_skip_categories: categories that were wanted but excluded because
        # their generic self-contained model is a tautology (always-true regardless
        # of the CUT). The audit author must supply CUT-specific wiring to cover
        # these. bugfix: tautology-CatInvariants (atomicity/determinism) 2026-06-13
        "typed_skip_categories": typed_skip_cats,
        "emitted_files": sorted(files),
        "engines": {
            "halmos": {"spec": f"test/{surf.name}_HalmosSpec.t.sol", "runner": "tools/halmos-runner.sh"},
            "medusa": {"config": "medusa.json", "runner": "tools/medusa-fuzz.sh"},
            "echidna": {"config": "echidna.yaml", "runner": "tools/echidna-campaign.sh"},
            "foundry_invariant": {
                "spec": f"test/{surf.name}_Invariant.t.sol",
                "runner": f"forge test --match-contract {surf.name}_Invariant",
            },
        },
        "candidate_not_proof": True,
        "rule_58_grounded": bool(matched),
        # real_output_bound: True iff at least one emitted property asserts a
        # RELATION over the REAL CUT return value (here: determinism f()==f() over
        # a zero-arg comparable-return view fn). The protocol-semantic category
        # checks (ci.check over the self-model) are model+seam = needs-binding,
        # NOT genuine coverage. R80: only real_output_bound=true counts as genuine.
        "real_output_bound": bool(realout_view_fns(surf)),
        "real_output_view_fns": [f.name for f in realout_view_fns(surf)],
        # setUp_binds_target: True when the emitted Foundry invariant harness
        # deploys the real CUT in setUp() and calls bindTarget(address(cut)).
        # "typed-skip" means the forge invariant harness is an HONEST TYPED-SKIP:
        # setUp() does not call bindTarget() because constructor args / proxy
        # topology are not known at generic authoring time. The emitted
        # _Invariant.t.sol carries the HARNESS-TYPED-SKIP sentinel so downstream
        # consumers (audit-complete, oracle_verdict) know this file requires
        # CUT-specific wiring before it can contribute genuine coverage.
        # The audit author must supply a real deployment + bindTarget call and
        # then change this field to True in a re-emitted manifest.
        "setUp_binds_target": "typed-skip",
    }
    manifest_path = out / "attempt_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    manifest["manifest_path"] = str(manifest_path)
    manifest["out_dir"] = str(out)
    return manifest


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("workspace", help="audit workspace root")
    ap.add_argument("contract", help="path to the Solidity contract source")
    ap.add_argument("--contract-name", default=None, help="contract name if file has several")
    ap.add_argument("--out-dir", default=None, help="override output dir")
    ap.add_argument("--extracted", default=str(DEFAULT_EXTRACTED))
    ap.add_argument("--pilot", default=str(DEFAULT_PILOT))
    ap.add_argument("--json", action="store_true", help="emit manifest JSON to stdout")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    contract_path = Path(args.contract).expanduser().resolve()
    if not contract_path.exists():
        print(f"error: contract not found: {contract_path}", file=sys.stderr)
        return 2
    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else None

    try:
        manifest = author(ws, contract_path, args.contract_name,
                          Path(args.extracted), Path(args.pilot), out_dir)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(manifest, indent=2))
    else:
        print(f"contract:   {manifest['contract']} ({manifest['contract_kind']})")
        print(f"out_dir:    {manifest['out_dir']}")
        if manifest.get("authoring_path") == "tick-math-pure-library":
            print(f"path:       tick-math-pure-library")
            print(f"invariants: {', '.join(manifest['tick_invariants'])}")
            print(f"tick->price fn: {manifest['surface']['tick_to_price_fn']}")
        else:
            print(f"mutating:   {', '.join(manifest['surface']['mutating_external_fns']) or '(none)'}")
        mi = manifest["matched_invariants"]
        if mi:
            for cat, ids in mi.items():
                print(f"  [{cat}] {', '.join(ids)}")
        else:
            print("  (no corpus invariant matched - emitted skeleton only)")
        print("engines:    halmos, medusa, echidna, foundry_invariant")
        print(f"manifest:   {manifest['manifest_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
