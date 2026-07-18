#!/usr/bin/env python3
"""authz-type-exhaustiveness.py - the AUTHZ/ROUTING DISPATCH TYPE-EXHAUSTIVENESS
screen (RANK-15 authorization-bypass-via-unhandled-type class).

GENERAL language-intrinsic completeness class (never a bug SHAPE). It instantiates
the north-star method ("a TRUSTED ENFORCEMENT is bypassable") for a soundness
property no wired capability owns: whether an authorization / routing DISPATCH over
a message-type / token-type / command-type / asset-type UNIVERSE is EXHAUSTIVE, and
whether the branch that catches a NON-enumerated type is a SAFE REJECT rather than a
permissive fall-through.

  DISPATCH D  : a type-switch (`switch v := x.(type) { case *A: ... }`), an enum /
      const value-switch, or a Solidity if/else-if chain on an enum/route/token/msg
      TYPE selector, that AUTHORIZES or PROCESSES known concrete types.
  UNIVERSE(T) : the declared set of concrete types / oneof members / enum values /
      interface implementors that the selector T can take at run time.
  HANDLED(D)  : the type cases with an explicit guarded branch in THIS dispatch.
  ATTACK / DEFECT : a NON-enumerated type in UNIVERSE(T)  HANDLED(D) reaches the
      dispatch's default / fall-through branch, and that branch does NOT reject
      (no panic / error-return / revert) - it processes the message, authorizes it,
      or returns a permissive value -> the authz guard is skipped for that type.

REASONING QUERY (a set-difference + branch-safety fact, NOT a grep for "switch" /
"default"):

    SURVIVORS = { D | ( UNIVERSE(type_of(D))  HANDLED(D) ) is non-empty
                      AND default_branch(D) is NOT a safe-reject }

    KEPT      = { D | HANDLED(D) covers UNIVERSE(type_of(D))   # exhaustive
                    OR default_branch(D) is a safe-reject }    # safe default

UNIVERSE derivation (fully enumerable vs advisory needs_source):
  * ONEOF-FAMILY: when the handled cases share a `Prefix_` family (proto oneof:
    `Event_ContractCall`, `Event_ContractCallWithToken` -> family `Event_`), the
    universe is every `type Prefix_* struct` declared in the substrate - fully
    enumerable.
  * CROSS-SWITCH UNION: the union of case-types seen across every dispatch that
    shares a family with D extends HANDLED even without declarations.
  * Solidity ENUM: universe = the members of the `enum T { A, B, C }` declaration.
  * If NEITHER a declaration family NOR a cross-switch peer extends HANDLED, the
    universe cannot be fully enumerated -> the row is emitted advisory=needs_source
    (an HONEST "cannot prove exhaustive", not a silent survivor and not a clean).

BIASES TOWARD SILENCE. A dispatch is only considered when it is authorization/
routing relevant (enclosing fn name or file path names an ante / handler / router /
dispatch / authz / command / event surface) AND it switches on a TYPE (interface
`.(type)` assertion, an enum/const family, or a Solidity enum selector). Among those
it stays silent whenever the dispatch is exhaustive OR its default is a safe reject.

ADVISORY-FIRST: every row carries advisory=True / auto_credit=False and
verdict='needs-source' (a set-difference is a lead, the impact is decided by reading
the fall-through body against the real type universe at run time). --fail-closed only
raises the exit code, and additionally fails when the *substrate is vacuous* (0
dispatches over a tree that DOES contain in-scope Go/Solidity - substrate_vacuous,
distinct from an honest cited-empty where dispatches exist and all are KEPT).

Languages: Go (.go) - type-switch + enum/const value-switch (primary; Cosmos
msg-server / ante / cross-chain command dispatch) and Solidity (.sol) - enum-typed
if/else-if / value-switch selector routing. Silent on every other tree.

Usage:
  --workspace/--ws <ws>   scan <ws>/src (or <ws>) -> sidecar ledger + summary
  --src-root <dir>        scan an arbitrary dir (rows as JSON, no sidecar)
  --file <f>              scan a single .go/.sol file (rows as JSON)
  --emit <path>          override the sidecar ledger path
  --check                re-read the emitted ledger, print cert verdict (advisory)
  --json                 machine summary to stdout
  --fail-closed          elevate exit code on any survivor OR a vacuous substrate
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

# --- reuse the canonical synthetic / codegen exclusion (single source of truth) ---
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
try:
    from synthetic_target_exclusion import (  # noqa: E402
        is_test_target_path,
        is_codegen_path,
        is_chimera_mutation_harness_path,
    )
except Exception:  # pragma: no cover - defensive: never let a missing lib crash the walk
    def is_test_target_path(p):  # type: ignore
        return False

    def is_codegen_path(p, workspace=None):  # type: ignore
        return False

    def is_chimera_mutation_harness_path(p):  # type: ignore
        return False

SCHEMA = "auditooor.authz_type_exhaustiveness.v1"
_SIDE_NAME = "authz_type_exhaustiveness_obligations.jsonl"
_STRICT_ENV = "AUDITOOOR_AUTHZ_TYPE_EXHAUSTIVENESS_FAILCLOSED"
_CAPABILITY = "AUTHZ_TYPE_EXHAUSTIVENESS"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmark", "benchmarks", "fuzz", "examples",
              "prior_audits", "reference", "docs", "tests", "test",
              "mocks", "mock", "testdata", "simulation", "simapp",
              "chimera_harnesses", "poc-tests", "lib", "node_modules"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|"
    r"fixtures|fuzz|simulation|simapp|chimera_harnesses|poc-tests|"
    r"prior_audits|reference)(/|$)")

# --- machine-generated source exclusion (proto .pb.go MUST be skipped: they carry
#     enormous non-authz field-number switches) -----------------------------------
_GENERATED_SUFFIXES = (
    ".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go", "_generated.go",
    ".pb.validate.go", ".cosmos_orm.go",
)
_GENERATED_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)


def _is_generated_source(path: Path) -> bool:
    if path.name.lower().endswith(_GENERATED_SUFFIXES):
        return True
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except (OSError, UnicodeError):
        return False
    return bool(_GENERATED_SENTINEL.search(head))


def _excluded_path(p: Path) -> bool:
    s = str(p)
    if is_test_target_path(s) or is_chimera_mutation_harness_path(s):
        return True
    if is_codegen_path(s):
        return True
    if _is_generated_source(p):
        return True
    return False


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        rp = dp.replace(os.sep, "/")
        if _TEST_HINT.search(rp):
            continue
        for f in fn:
            low = f.lower()
            if not (low.endswith(".go") or low.endswith(".sol")):
                continue
            if low.endswith("_test.go") or low.endswith(".t.sol") or \
               low.endswith(".s.sol"):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            if _excluded_path(p):
                continue
            yield p


# ---------------------------------------------------------------------------
# Comment / string masker (Go + Solidity). // line, /* */ block, "..." strings,
# Go `...` raw strings, Go '\n' rune literals. Preserves newlines + per-line length
# so line indices stay source-accurate. Errs toward SILENCE.
# ---------------------------------------------------------------------------
def _mask(text: str) -> str:
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            if j == -1:
                out.append(" " * (n - i))
                break
            out.append("  " + " " * (j - i - 2))
            i = j
            continue
        if c == "/" and nxt == "*":
            out.append("  ")
            i += 2
            while i < n:
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    out.append("  ")
                    i += 2
                    break
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        if c == "`":  # Go raw string
            out.append(" ")
            i += 1
            while i < n and text[i] != "`":
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
            continue
        if c == '"':
            out.append(" ")
            i += 1
            while i < n:
                if text[i] == "\\":
                    out.append("  " if i + 1 < n else " ")
                    i += 2
                    continue
                if text[i] == '"':
                    out.append(" ")
                    i += 1
                    break
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        if c == "'":  # Go rune literal (Solidity has no char literal)
            m = re.match(r"'(?:\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|.)|[^'\\\n])'",
                         text[i:])
            if m:
                out.append(" " * len(m.group(0)))
                i += len(m.group(0))
                continue
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _match_brace(text: str, open_idx: int) -> int:
    """Return index just past the matching '}' for the '{' at open_idx."""
    depth = 0
    i, n = open_idx, len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _line_of(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


# ---------------------------------------------------------------------------
# Authorization / routing relevance
# ---------------------------------------------------------------------------
_AUTHZ_FN_RE = re.compile(
    r"(ante|authz|author|permission|access|admin|role|guard|handle|handler|"
    r"route|router|dispatch|execute|process|validate|verif|check|refund|reward|"
    r"command|event|msg|sign|deliver|apply|migrate|proposal|gov|nexus|"
    r"crosschain|cross_chain|relay|forward|redeem|withdraw|deposit|transfer)",
    re.I)
_AUTHZ_PATH_RE = re.compile(
    r"(ante|handler|keeper|msg_?server|abci|router|dispatch|authz|access|"
    r"nexus|evm|gateway|command|event|reward|gov|crosschain|relay)", re.I)


def _authz_relevant(fn_name: str, rel_path: str, switch_ctx: str) -> bool:
    """True when the dispatch is on an authorization / routing surface. Requires the
    enclosing function OR the file path OR the switch context to name an authz/route
    surface. Biases to silence: a switch in a pure math/format helper is dropped."""
    if _AUTHZ_FN_RE.search(fn_name):
        return True
    if _AUTHZ_PATH_RE.search(rel_path):
        return True
    if _AUTHZ_FN_RE.search(switch_ctx or ""):
        return True
    return False


# ---------------------------------------------------------------------------
# Default-branch safety classifier (the SECOND non-vacuity hinge)
# ---------------------------------------------------------------------------
# A default (or fall-through) branch is a SAFE REJECT when it PANICS, returns an
# error / false, reverts, or is provably unreachable. It is UNSAFE (permissive) when
# absent, empty, `return nil` (success), `return next(...)` (passes through the
# guard), break/continue, or a bare permissive value.
_SAFE_DEFAULT_RE = re.compile(
    r"\b(panic|revert|require\s*\(|assert\s*\(|_ = fmt|Errorf|errorsmod\s*\.\s*Wrap|"
    r"sdkerrors|status\s*\.\s*Error|ErrInvalid|ErrUnknown|ErrUnauthorized|"
    r"ErrUnsupported|return\s+false\b|return\s+err\b|return\s+.*[Ee]rr(or)?\b|"
    r"t\s*\.\s*Fatal|log\s*\.\s*Fatal|os\s*\.\s*Exit|unreachable|"
    r"throw\b|revert\s*[A-Za-z0-9_]*\s*\()")
_UNSAFE_DEFAULT_RE = re.compile(
    r"return\s+nil\b|return\s+next\s*\(|return\s+ctx\s*,|return\s*$|"
    r"^\s*break\b|^\s*continue\b|return\s+true\b")


def classify_default_safety(default_body: str, present: bool) -> str:
    """Classify the fall-through branch. Returns 'safe-reject' | 'unsafe' | 'unknown'.

    A MISSING default in a type-switch means unmatched types silently skip the
    dispatch body -> 'unsafe' (the guard does not run for them). A present default is
    'safe-reject' when it panics / errors / reverts, else 'unsafe'.

    Neutralising this to a constant 'safe-reject' makes every survivor disappear (the
    second non-vacuity hinge); a constant 'unsafe' floods every non-exhaustive
    dispatch."""
    if not present:
        return "unsafe"  # no default: unmatched types fall through the guard
    body = default_body or ""
    if _SAFE_DEFAULT_RE.search(body):
        return "safe-reject"
    if _UNSAFE_DEFAULT_RE.search(body) or body.strip() == "":
        return "unsafe"
    # a default that DOES something but neither rejects nor is obviously permissive:
    # treat as unsafe-lean (it processes the unknown type rather than rejecting).
    return "unsafe"


# ---------------------------------------------------------------------------
# Go: type declarations + function iteration
# ---------------------------------------------------------------------------
_GO_TYPE_DECL_RE = re.compile(r"\btype\s+([A-Za-z_]\w*)\s+(struct|interface)\b")
_GO_FUNC_RE = re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\(")
# a type-switch header:  switch [ident :=] EXPR.(type) {
_GO_TYPESWITCH_RE = re.compile(
    r"\bswitch\s+(?:[A-Za-z_]\w*\s*:?=\s*)?([A-Za-z_][\w\.\(\)]*)\s*\.\s*\(\s*type\s*\)\s*\{")


def _strip_ptr_pkg(t: str) -> str:
    """Normalise a case type: strip leading '*' and a package qualifier."""
    t = t.strip().lstrip("*").strip()
    if "." in t:
        t = t.split(".")[-1]
    return t


def _parse_switch_cases(text: str, brace_open: int):
    """Parse a switch body starting at the '{' brace_open. Return
    (handled_types[list of normalised names], default_present, default_body).
    Only top-level `case`/`default` labels (depth==1 relative to the switch) count.
    handled_types are the case operands (for a type-switch: type names; for a value
    switch: the raw case tokens)."""
    end = _match_brace(text, brace_open)
    body = text[brace_open + 1:end - 1]
    handled = []
    default_present = False
    default_body = ""
    # walk labels at nesting depth 0 within body
    depth = 0
    i, n = 0, len(body)
    labels = []  # (kind, operand, start_of_body)
    while i < n:
        c = body[i]
        if c in "{([":
            depth += 1
            i += 1
            continue
        if c in "})]":
            depth -= 1
            i += 1
            continue
        if depth == 0:
            m = re.match(r"(?:^|\n)\s*(case\b([^:{]*)|default\b)\s*:", body[i:])
            # match at line-ish start: require preceding char is newline or start
            if m and (i == 0 or body[i] in "\n" or body[max(0, i - 1)] == "\n"
                      or re.match(r"\s*(case|default)\b", body[i:])):
                if m.group(1).startswith("case"):
                    labels.append(("case", m.group(2), i + m.end()))
                else:
                    labels.append(("default", "", i + m.end()))
                i += m.end()
                continue
        i += 1
    # slice bodies between labels
    for idx, (kind, operand, bstart) in enumerate(labels):
        bend = labels[idx + 1][2] if idx + 1 < len(labels) else n
        # trim the trailing label match length of next (approx: next label starts at
        # its 'case'/'default'); good enough since we only classify default text.
        seg = body[bstart:bend]
        if kind == "default":
            default_present = True
            default_body = seg
        else:
            for part in operand.split(","):
                nm = _strip_ptr_pkg(part)
                if nm:
                    handled.append(nm)
    return handled, default_present, default_body


def _family_of(names) -> str:
    """Return the common `Prefix_` oneof family shared by >=2 handled names, else ''.
    e.g. {Event_ContractCall, Event_ContractCallWithToken} -> 'Event_'."""
    prefixes = {}
    for nm in names:
        if "_" in nm:
            pfx = nm.split("_", 1)[0] + "_"
            prefixes.setdefault(pfx, 0)
            prefixes[pfx] += 1
    for pfx, cnt in prefixes.items():
        if cnt >= 2:
            return pfx
    # single handled member still carries a family (universe may be bigger)
    for nm in names:
        if "_" in nm:
            return nm.split("_", 1)[0] + "_"
    return ""


# ---------------------------------------------------------------------------
# Solidity: enum declarations + enum-typed dispatch
# ---------------------------------------------------------------------------
_SOL_ENUM_RE = re.compile(r"\benum\s+([A-Za-z_]\w*)\s*\{([^}]*)\}")
_SOL_FUNC_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")


def _sol_enum_universe(text: str):
    """Map enum name -> [members]. Universe for Solidity enum dispatch."""
    out = {}
    for m in _SOL_ENUM_RE.finditer(text):
        members = [x.strip() for x in m.group(2).split(",") if x.strip()]
        out[m.group(1)] = members
    return out


# ---------------------------------------------------------------------------
# Pass 1: whole-tree universe substrate (Go type decls + cross-switch families)
# ---------------------------------------------------------------------------
def build_substrate(files):
    """Return (go_type_decls:set, family_members:dict prefix->set, sol_enums:dict).
    go_type_decls = every declared concrete type name; family_members groups them by
    oneof prefix. Also folds in every case-type seen across type-switches so the
    cross-switch union is available even when a member has no local declaration."""
    go_type_decls = set()
    family_members = {}
    sol_enums = {}
    for p, rel, text in files:
        if rel.endswith(".go"):
            for m in _GO_TYPE_DECL_RE.finditer(text):
                nm = m.group(1)
                go_type_decls.add(nm)
                if "_" in nm:
                    pfx = nm.split("_", 1)[0] + "_"
                    family_members.setdefault(pfx, set()).add(nm)
            # cross-switch union: every case type contributes to its family
            for sm in _GO_TYPESWITCH_RE.finditer(text):
                bo = text.find("{", sm.end() - 1)
                if bo == -1:
                    continue
                handled, _, _ = _parse_switch_cases(text, bo)
                for nm in handled:
                    if "_" in nm:
                        pfx = nm.split("_", 1)[0] + "_"
                        family_members.setdefault(pfx, set()).add(nm)
        elif rel.endswith(".sol"):
            for name, members in _sol_enum_universe(text).items():
                sol_enums[name] = members
    return go_type_decls, family_members, sol_enums


def _universe_for(handled, family_members):
    """Compute (universe:set, enumerable:bool) for a Go type-switch given its handled
    set and the tree-wide family_members. Fully enumerable when a oneof family is
    resolved; otherwise the union may still extend handled (enumerable via peers)."""
    fam = _family_of(handled)
    if fam and fam in family_members:
        uni = set(family_members[fam])
        # enumerable when the family has real declared/observed members beyond noise
        return uni, True
    return set(handled), False


# ---------------------------------------------------------------------------
# Go dispatch scan
# ---------------------------------------------------------------------------
def _enclosing_fn(text: str, off: int) -> str:
    best = ""
    for m in _GO_FUNC_RE.finditer(text):
        if m.start() > off:
            break
        best = m.group(1)
    return best


def scan_go(rel, text, family_members):
    rows = []
    for sm in _GO_TYPESWITCH_RE.finditer(text):
        selector_expr = sm.group(1)
        bo = text.find("{", sm.end() - 1)
        if bo == -1:
            continue
        handled, default_present, default_body = _parse_switch_cases(text, bo)
        if not handled:
            continue
        line = _line_of(text, sm.start())
        fn = _enclosing_fn(text, sm.start())
        ctx = text[sm.start():min(len(text), sm.start() + 200)]
        if not _authz_relevant(fn, rel, ctx + " " + selector_expr):
            continue
        universe, enumerable = _universe_for(handled, family_members)
        missing = sorted(set(universe) - set(handled))
        non_exhaustive = len(missing) > 0
        default_safety = classify_default_safety(default_body, default_present)
        unsafe_default = default_safety != "safe-reject"
        rows.append(_mk_row(
            rel, line, fn, "go", "type-switch", selector_expr,
            handled, missing, non_exhaustive, enumerable,
            default_present, default_safety, unsafe_default))
    return rows


# ---------------------------------------------------------------------------
# Solidity dispatch scan (enum-typed if/else-if chain OR value-switch)
# ---------------------------------------------------------------------------
_SOL_IFCHAIN_ENUM_RE = re.compile(
    r"\bif\s*\(\s*([A-Za-z_]\w*)\s*==\s*([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\)")


def scan_sol(rel, text, sol_enums):
    """Detect a Solidity if/else-if chain dispatching on an enum-typed selector.
    Universe = enum members. HANDLED = the members compared in the chain. Survivor
    when some member is unhandled AND the trailing else is not a revert."""
    rows = []
    # group consecutive `X == Enum.Member` comparisons within one function scope by
    # (selector_var, enum_type)
    chains = {}  # (var, enum) -> {members:set, first_off:int}
    for m in _SOL_IFCHAIN_ENUM_RE.finditer(text):
        var, enum_ty, member = m.group(1), m.group(2), m.group(3)
        if enum_ty not in sol_enums:
            continue
        key = (var, enum_ty)
        c = chains.setdefault(key, {"members": set(), "first_off": m.start(),
                                    "last_off": m.start()})
        c["members"].add(member)
        c["last_off"] = m.end()
    for (var, enum_ty), c in chains.items():
        universe = set(sol_enums[enum_ty])
        handled = c["members"]
        missing = sorted(universe - handled)
        if not missing:
            continue  # exhaustive
        line = _line_of(text, c["first_off"])
        fn = _sol_enclosing_fn(text, c["first_off"])
        if not _authz_relevant(fn, rel, var + " " + enum_ty):
            continue
        # look at the tail of the chain for a trailing `else { ... }`
        tail = text[c["last_off"]:c["last_off"] + 400]
        em = re.search(r"\belse\b", tail)
        default_present = bool(em)
        default_body = tail[em.end():em.end() + 200] if em else ""
        default_safety = classify_default_safety(default_body, default_present)
        unsafe_default = default_safety != "safe-reject"
        rows.append(_mk_row(
            rel, line, fn, "solidity", "enum-if-chain",
            f"{var}:{enum_ty}", sorted(handled), missing, True, True,
            default_present, default_safety, unsafe_default))
    return rows


def _sol_enclosing_fn(text: str, off: int) -> str:
    best = ""
    for m in _SOL_FUNC_RE.finditer(text):
        if m.start() > off:
            break
        best = m.group(1)
    return best


# ---------------------------------------------------------------------------
# Row construction + verdict
# ---------------------------------------------------------------------------
def _stable_id(rel, fn, selector, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{selector}|{line}".encode())
    return h.hexdigest()[:16]


def _mk_row(rel, line, fn, lang, dispatch_kind, selector, handled, missing,
            non_exhaustive, enumerable, default_present, default_safety,
            unsafe_default):
    survivor = bool(non_exhaustive and unsafe_default and enumerable)
    if not enumerable:
        # universe not fully enumerable: honest advisory, NOT a confirmed survivor
        verdict = "needs-source"
        advisory = "needs_source"
    elif survivor:
        verdict = "needs-source"
        advisory = True
    else:
        verdict = "kept"
        advisory = True
    if survivor:
        q = (f"`{fn}` dispatches on type `{selector}` ({dispatch_kind}) handling "
             f"{sorted(handled)} but the type universe also contains {missing}; the "
             f"fall-through branch is `{default_safety}` (not a safe reject). Can a "
             f"caller submit a `{missing[0]}` so it reaches the non-rejecting default "
             f"and bypasses / is processed WITHOUT the authorization the handled "
             f"cases enforce (unhandled-type authz bypass)?")
    elif not enumerable:
        q = (f"`{fn}` dispatches on type `{selector}` handling {sorted(handled)}; the "
             f"full type universe could NOT be enumerated from the substrate (no "
             f"oneof family / peer switch / enum decl). Read the interface's "
             f"implementors: is any concrete type unhandled AND does the "
             f"`{default_safety}` default fail to reject it?")
    else:
        reason = ("exhaustive" if not non_exhaustive else
                  f"safe-reject default ({default_safety})")
        q = (f"`{fn}` dispatch on `{selector}` is KEPT ({reason}); unhandled types "
             f"cannot bypass the guard (silent).")
    return {
        "schema": SCHEMA,
        "capability": _CAPABILITY,
        "obligation_type": "authz-type-exhaustiveness",
        "id": _stable_id(rel, fn, selector, line),
        "file": rel,
        "line": line,
        "function": fn,
        "lang": lang,
        "dispatch_kind": dispatch_kind,
        "selector": selector,
        "handled": sorted(handled),
        "handled_count": len(set(handled)),
        "missing_types": missing,
        "non_exhaustive": non_exhaustive,
        "universe_enumerable": enumerable,
        "default_present": default_present,
        "default_safety": default_safety,
        "unsafe_default": unsafe_default,
        "survivor": survivor,
        "verdict": verdict,
        "advisory": advisory,
        "auto_credit": False,
        "source_refs": [f"{rel}:{line}"],
        "attack_class": "authorization-bypass-unhandled-type",
        "likely_severity": "high",
        "question": q,
        "next_command": f"python3 tools/authz-type-exhaustiveness.py --file {rel}",
    }


# ---------------------------------------------------------------------------
# Tree driver
# ---------------------------------------------------------------------------
def _load_files(root: Path):
    files = []
    for p in _iter_source_files(root):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            raw = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        files.append((p, rel, _mask(raw)))
    return files


def scan_tree(root: Path):
    files = _load_files(root)
    go_decls, family_members, sol_enums = build_substrate(files)
    rows = []
    raw_dispatch_constructs = 0
    for p, rel, text in files:
        try:
            if rel.endswith(".go"):
                raw_dispatch_constructs += len(_GO_TYPESWITCH_RE.findall(text))
                rows.extend(scan_go(rel, text, family_members))
            elif rel.endswith(".sol"):
                raw_dispatch_constructs += len(_SOL_ENUM_RE.findall(text))
                rows.extend(scan_sol(rel, text, sol_enums))
        except Exception:
            continue
    has_substrate = any(rel.endswith(".go") or rel.endswith(".sol")
                        for _, rel, _ in files)
    return rows, has_substrate, raw_dispatch_constructs


def scan_file(path: Path, rel: str):
    raw = path.read_text(encoding="utf-8", errors="ignore")
    text = _mask(raw)
    files = [(path, rel, text)]
    go_decls, family_members, sol_enums = build_substrate(files)
    rows = []
    if rel.endswith(".go"):
        rows = scan_go(rel, text, family_members)
    elif rel.endswith(".sol"):
        rows = scan_sol(rel, text, sol_enums)
    return rows


def _summary(rows, has_substrate, raw_constructs=0):
    dispatches = len(rows)
    non_exhaustive = [r for r in rows if r.get("non_exhaustive")]
    unsafe_default = [r for r in rows if r.get("unsafe_default")]
    survivors = [r for r in rows if r.get("survivor")]
    kept = [r for r in rows if r.get("verdict") == "kept"]
    needs_source = [r for r in rows if r.get("advisory") == "needs_source"]
    if not has_substrate:
        substrate = "substrate_absent"
    elif dispatches == 0 and raw_constructs == 0:
        # in-scope src exists but the type-dispatch IDIOM is entirely absent (no
        # type-switch / enum): honest "not applicable", NOT a tool gap - do not
        # fail-closed on this.
        substrate = "idiom_absent"
    elif dispatches == 0:
        # type-switches/enums EXIST but 0 became authz dispatches: genuinely vacuous
        # (all filtered) - a possible tool/relevance gap worth failing on.
        substrate = "substrate_vacuous"
    else:
        substrate = "substrate_present"
    if survivors:
        verdict = "survivors"
    elif dispatches > 0:
        verdict = "cited-empty"  # dispatches exist, all KEPT/needs_source
    else:
        verdict = "no-dispatch"
    return {
        "schema": SCHEMA,
        "capability": _CAPABILITY,
        "dispatches": dispatches,
        "non_exhaustive": len(non_exhaustive),
        "unsafe_default": len(unsafe_default),
        "survivors": len(survivors),
        "kept": len(kept),
        "needs_source": len(needs_source),
        "substrate": substrate,
        "verdict": verdict,
        "advisory": True,
        "auto_credit": False,
    }


def _emit_sidecar(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return path


def _resolve_ws(arg: str) -> Path:
    ws = Path(arg)
    if not ws.is_absolute():
        for base in ("/Users/wolf/audits", os.getcwd()):
            cand = Path(base) / arg
            if cand.exists():
                return cand
    return ws


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Authorization/routing dispatch type-exhaustiveness screen "
                    "(Go + Solidity, advisory, RANK-15).")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--src-root")
    ap.add_argument("--file")
    ap.add_argument("--emit")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true")
    args = ap.parse_args(argv)

    fail_closed = args.fail_closed or os.environ.get(_STRICT_ENV, "").strip() not in (
        "", "0", "false", "no")

    if args.file:
        p = Path(args.file)
        rows = scan_file(p, p.name)
        print(json.dumps(rows, indent=2))
        return 1 if (fail_closed and any(r["survivor"] for r in rows)) else 0

    if args.src_root:
        rows, has_sub, raw = scan_tree(Path(args.src_root))
        print(json.dumps(rows, indent=2))
        surv = any(r["survivor"] for r in rows)
        vac = has_sub and not rows and raw > 0
        return 1 if (fail_closed and (surv or vac)) else 0

    if not args.workspace:
        ap.error("one of --workspace / --src-root / --file is required")

    ws = _resolve_ws(args.workspace)
    side = Path(args.emit) if args.emit else ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines()
                    if l.strip()]
        summ = _summary(rows, has_substrate=True)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (fail_closed and summ["survivors"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows, has_sub, raw = scan_tree(root)
    _emit_sidecar(side, rows)
    summ = _summary(rows, has_sub, raw)
    print(json.dumps(summ, indent=2))
    bad = summ["survivors"] or summ["substrate"] == "substrate_vacuous"
    return 1 if (fail_closed and bad) else 0


if __name__ == "__main__":
    sys.exit(main())
