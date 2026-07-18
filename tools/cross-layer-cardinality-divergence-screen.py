#!/usr/bin/env python3
"""cross-layer-cardinality-divergence-screen.py - the CROSS-LAYER
COMMITTED-vs-CONSUMED SET-CARDINALITY-DIVERGENCE screen (EXT04).

GENERAL LOGIC / whole-system INVARIANT class (never a bug SHAPE, never an impact
silo). It instantiates one architecture-level soundness property that no single
per-function detector owns:

  SHARED SERIALIZED ARTIFACT : a batch / array / message / chunk that MORE THAN
    ONE component iterates or validates - a "committing / proving" loop and a
    "consuming / settling" loop, or two validators, over the SAME buffer.
  THE INVARIANT             : both sides must derive their iteration bound from
    the SAME authenticated cardinality (committed_count == consumed_count ==
    physical_length), OR elements outside a declared-real range must be provably
    inert AND that inertness enforced by the committing side.
  THE DEFECT (net-new)      : the ABSENCE of a cross-loop cardinality-binding
    invariant on a SHARED iteration bound. Layer A loops to bound_A over the
    buffer; layer B loops to a DIFFERENT bound_B over the SAME buffer; nothing
    forces bound_A == bound_B (or ties either to the buffer's physical length).
    An attacker sets the count BELOW the physical length and packs extra
    state-changing elements past it (trusted by A, skipped by B), or ABOVE it so
    B consumes elements A never committed to. Every single-component detector
    passes because each loop is individually correct.

Anchor: Aztec Connect settlement-boundary bypass (Jun 2026, ~$2.28M). The ZK
proof committed to a full 32-row inner-rollup chunk; the L1 settlement loop
stopped at attacker-set numRealTxs=1. A deposit packed at row 1 was proven-valid
but never settled - minting unbacked balance.

WHAT IT DOES (the net-new PAIRING no wired cap performs): per file it groups
loops by the buffer they index, and for every buffer touched by >=2 loops it
DIFFS THEIR BOUNDS. It folds a bound to the buffer's PHYSICAL length when the
bound is `buf.length` / `len(buf)`, an alias of that length, or the size the
buffer was allocated with (`new T[](n)` / `make([]T, n)`). A buffer iterated
under >=2 DISTINCT (post-fold) bounds - at least one of which is NOT the buffer's
own physical length - is a cardinality-divergence lead UNLESS an `==`/`!=`
guard binds the two bounds together somewhere in the touching functions.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode;
the opt-in env AUDITOOOR_CARDINALITY_STRICT (or --strict) only raises the exit
code when a divergence fired.

Language-general: Solidity (.sol) and Go (.go). Silent on other trees. Machine-
generated code (.pb.go/.pulsar.go/_gen.go + "Code generated ... DO NOT EDIT")
and test files are skipped.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/<sidecar>.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar write)
  --file <f>         scan a single .sol/.go file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a divergence fired
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.cross_layer_cardinality_divergence_hypotheses.v1"
_SIDE_NAME = "cross_layer_cardinality_divergence_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_CARDINALITY_STRICT"
_CAPABILITY = "EXT04"
_CLASS = "cross-layer-committed-vs-consumed-set-cardinality-divergence"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "mocks", "mock", "dependencies",
              "third_party", "third-party", "testdata"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|fixtures)(/|$)")

# --- generated-source exclusion (copied from declared-control-mutator screen) --
_GENERATED_SUFFIXES = (
    ".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go", "_generated.go",
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


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not (low.endswith(".sol") or low.endswith(".go")):
                continue
            if low.endswith("_test.go") or low.endswith(".t.sol"):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            if _is_generated_source(p):
                continue
            yield p


# --- comment/string-aware brace matcher --------------------------------------
def _match_brace(text: str, open_idx: int) -> int:
    """Return index of the '}' matching the '{' at open_idx, or -1."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            j = text.find('\n', i)
            i = n if j < 0 else j
            continue
        if c == '/' and i + 1 < n and text[i + 1] == '*':
            j = text.find('*/', i + 2)
            i = n if j < 0 else j + 2
            continue
        if c == '"' or c == "'" or c == '`':
            q = c
            i += 1
            while i < n:
                if text[i] == '\\' and q != '`':
                    i += 2
                    continue
                if text[i] == q:
                    break
                i += 1
            i += 1
            continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


# --- function extraction (brace-matched, Solidity + Go) ----------------------
_FN_DECL_RE = re.compile(
    r"(?m)^[ \t]*(?:"
    r"function\s+([A-Za-z_]\w*)"                 # Solidity function foo
    r"|(constructor)\b"                           # Solidity constructor
    r"|(fallback|receive)\s*\("                  # Solidity fallback/receive
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"   # Go func (recv) Foo / func Foo
    r")")


def _fn_name(m):
    return m.group(1) or m.group(2) or m.group(3) or m.group(4)


def _iter_functions(text: str):
    """Yield (name, body_text, body_start_offset) for each top-level function."""
    for m in _FN_DECL_RE.finditer(text):
        name = _fn_name(m)
        if not name:
            continue
        # find the body-opening '{' before any statement-terminating ';'
        semi = text.find(';', m.end())
        brace = text.find('{', m.end())
        if brace < 0:
            continue
        if 0 <= semi < brace:
            # declaration only (interface / abstract) - no body
            continue
        close = _match_brace(text, brace)
        if close < 0:
            continue
        yield name, text[brace + 1:close], brace + 1


# --- bound normalization -----------------------------------------------------
_WS = re.compile(r"\s+")
# an array-or-field reference may carry `.` and subscripts (`s_cfg[id].signers`)
_ARR_REF = r"[A-Za-z_][A-Za-z0-9_.\[\]]*"
_LEN_DOT = re.compile(r"^(" + _ARR_REF + r")\.length(?:\(\))?$")
_LEN_FN = re.compile(r"^len\((" + _ARR_REF + r")\)$")
_SIZE_CALL = re.compile(r"^(" + _ARR_REF + r")\.(?:size|len)\(\)$")
_LEN_TOKEN = re.compile(r"^len\(.+\)$")
_NUMERIC = re.compile(r"^(?:0x[0-9a-fA-F]+|\d+)$")
_CONST_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")
# a leading numeric type-cast around the real bound: uint32(len(x)), int(n)
_CAST = re.compile(
    r"^(?:u?int\d*|byte|rune|uint|int|uint256|uint128|uint64|uint32|uint16|uint8"
    r"|uint160|size_t|uintptr)\((.*)\)$")


def _canon(s: str) -> str:
    return _WS.sub("", s)


def _strip_casts(c: str) -> str:
    for _ in range(3):
        m = _CAST.match(c)
        if not m:
            break
        c = m.group(1)
    return c


def _phys_of(expr_canon: str, alias_map: dict):
    """If expr denotes the physical length of some array X, return canon(X)."""
    for rx in (_LEN_DOT, _LEN_FN, _SIZE_CALL):
        m = rx.match(expr_canon)
        if m:
            return m.group(1)
    if expr_canon in alias_map:
        return alias_map[expr_canon]
    return None


def _norm_bound(b: str, alias_map: dict) -> str:
    c = _strip_casts(_canon(b))
    ph = _phys_of(c, alias_map)
    if ph is not None:
        return "len(%s)" % ph
    return c


_CONST_EXPR = re.compile(r"^[A-Z_][A-Z0-9_+\-*/%().]*$")

# --- language-aware declared-constant detection ------------------------------
# The ALL_CAPS naming heuristic (`_CONST_NAME`/`_CONST_EXPR`) is Solidity-only:
# Go package-level constants are conventionally CamelCase/PascalCase and Solidity
# `immutable`s are often mixedCase, so a screaming-snake proxy misclassifies
# `Depth` / `maxDepth` bounds as attacker counts and sprays on the canonical
# Merkle `zeroes[DEPTH]` vs `zeroes[DEPTH-1]` idiom. We additionally collect the
# constant/immutable identifiers ACTUALLY declared in the file and treat a bound
# built only from those identifiers + numeric literals as structural.
_DECL_CONST_SOL = re.compile(r"\b(?:constant|immutable)\s+([A-Za-z_]\w*)")
_DECL_CONST_GO_SINGLE = re.compile(r"\bconst\s+([A-Za-z_]\w*)")
_DECL_CONST_GO_BLOCK = re.compile(r"\bconst\s*\(([^)]*)\)", re.S)
_GO_BLOCK_LINE_IDENT = re.compile(r"(?m)^\s*([A-Za-z_]\w*)")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
# after stripping identifiers, a const-arith bound may only contain digits,
# whitespace and arithmetic/paren operators (no `.` field access, no `[`).
_CONST_ARITH_RESIDUE = re.compile(r"^[\s\d+\-*/%()]*$")


def _collect_declared_constants(text: str) -> frozenset:
    """Set of constant/immutable identifier names DECLARED in this file.

    Solidity `<type> [vis] (constant|immutable) NAME ...`, Go `const NAME = ...`
    and Go `const ( NAME ...; NAME ... )` blocks. Language-appropriate and
    conservative: over-collecting a name only ever SUPPRESSES a fire (a bound
    that reuses a declared-constant name), which is the safe direction for an
    advisory FP-control."""
    names = set()
    for m in _DECL_CONST_SOL.finditer(text):
        names.add(m.group(1))
    for m in _DECL_CONST_GO_SINGLE.finditer(text):
        names.add(m.group(1))
    for m in _DECL_CONST_GO_BLOCK.finditer(text):
        for lm in _GO_BLOCK_LINE_IDENT.finditer(m.group(1)):
            names.add(lm.group(1))
    return frozenset(names)


def _is_declared_const_expr(token: str, declared_consts) -> bool:
    """True when `token` is a declared constant/immutable identifier, or an
    arithmetic expression composed ONLY of such identifiers and numeric literals
    (e.g. `Depth`, `Depth-1`, `maxDepth-1`). Language-aware replacement for the
    ALL_CAPS-only naming proxy."""
    if not declared_consts:
        return False
    idents = _IDENT_RE.findall(token)
    if not idents:
        return False            # pure-numeric handled by _NUMERIC upstream
    if any(idn not in declared_consts for idn in idents):
        return False            # some token is NOT a declared constant
    residue = _IDENT_RE.sub(" ", token)
    return bool(_CONST_ARITH_RESIDUE.match(residue))


def _is_scalar_count(token: str, declared_consts=frozenset()) -> bool:
    """A token that is a genuine attacker-suppliable cardinality COUNT - not the
    physical length of any array, not a compile-time constant/literal."""
    if token == "PHYS":
        return False
    if _LEN_TOKEN.match(token):
        return False            # len(X) of some sibling array
    if _NUMERIC.match(token):
        return False            # fixed structural literal (crypto schedules etc.)
    if _CONST_NAME.match(token):
        return False            # ALL_CAPS compile-time constant (naming heuristic)
    if _CONST_EXPR.match(token):
        return False            # ALL_CAPS constant arithmetic expr (DEPTH-1 etc.)
    if _is_declared_const_expr(token, declared_consts):
        return False            # declared constant/immutable (language-aware)
    return True


# --- alias / allocation maps (per function) ----------------------------------
_ALIAS_SOL = re.compile(
    r"(?:\buint\d*\s+|\bint\d*\s+)?([A-Za-z_]\w*)\s*=\s*"
    r"([A-Za-z_][A-Za-z0-9_.]*)\.length\b")
_ALIAS_GO = re.compile(
    r"\b([A-Za-z_]\w*)\s*:?=\s*len\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)")
_ALLOC_SOL = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*new\s+[\w.]+\[\]\(\s*([^;){}]+?)\s*\)")
_ALLOC_GO = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.]*)\s*:?=\s*make\(\s*\[\][^,]+,\s*([^,){}]+?)\s*[,)]")


def _build_maps(body: str):
    alias_map = {}
    alloc_map = {}
    for m in _ALIAS_SOL.finditer(body):
        alias_map[_canon(m.group(1))] = _canon(m.group(2))
    for m in _ALIAS_GO.finditer(body):
        alias_map[_canon(m.group(1))] = _canon(m.group(2))
    for m in _ALLOC_SOL.finditer(body):
        alloc_map[_canon(m.group(1))] = _canon(m.group(2))
    for m in _ALLOC_GO.finditer(body):
        alloc_map[_canon(m.group(1))] = _canon(m.group(2))
    return alias_map, alloc_map


# --- loop extraction ---------------------------------------------------------
_FOR_SOL = re.compile(r"\bfor\s*\(([^{;]*;[^{]*)\)\s*\{")
_FOR_GO = re.compile(r"\bfor\b([^{\n]*?)\{")
_COND_LT = re.compile(r"([A-Za-z_]\w*)\s*(<=|<)\s*(.+)")
_COND_GT = re.compile(r"(.+?)\s*(>=|>)\s*([A-Za-z_]\w*)\s*$")


def _extract_cond_bound(cond: str):
    """From a loop condition return (loop_var, bound_expr) or None."""
    cond = cond.strip()
    if not cond:
        return None
    # take the first comparison clause (ignore && trailing guards)
    cond = re.split(r"&&|\band\b", cond)[0].strip()
    m = _COND_LT.match(cond)
    if m:
        return m.group(1), m.group(3).strip()
    m = _COND_GT.match(cond)
    if m:
        return m.group(3), m.group(1).strip()
    return None


def _iter_loops_in_body(body: str, ext: str):
    """Yield (loop_var, bound_expr, body_text, header_offset)."""
    seen = set()
    # Solidity 3-clause and Go 3-clause share the paren form
    for m in _FOR_SOL.finditer(body):
        header = m.group(1)
        parts = header.split(';')
        cond = parts[1] if len(parts) >= 2 else parts[0]
        cb = _extract_cond_bound(cond)
        if not cb:
            continue
        brace = body.find('{', m.end() - 1)
        if brace < 0:
            continue
        close = _match_brace(body, brace)
        if close < 0:
            continue
        seen.add(m.start())
        yield cb[0], cb[1], body[brace + 1:close], m.start()
    if ext == ".go":
        for m in _FOR_GO.finditer(body):
            if m.start() in seen:
                continue
            header = m.group(1).strip()
            if not header or header.startswith('range') or ' range ' in (' ' + header):
                continue
            if ';' in header:
                parts = header.split(';')
                cond = parts[1] if len(parts) >= 2 else parts[0]
            else:
                cond = header  # while-style `for cond {`
            cb = _extract_cond_bound(cond)
            if not cb:
                continue
            brace = body.find('{', m.end() - 1)
            if brace < 0:
                continue
            close = _match_brace(body, brace)
            if close < 0:
                continue
            yield cb[0], cb[1], body[brace + 1:close], m.start()


def _indexed_buffers(loop_body: str, var: str):
    """Return canon buffer names indexed by `var` inside the loop body."""
    rx = re.compile(r"([A-Za-z_][A-Za-z0-9_.]*)\[\s*" + re.escape(var) + r"\b")
    out = set()
    for m in rx.finditer(loop_body):
        out.add(_canon(m.group(1)))
    return out


# --- binding detection -------------------------------------------------------
def _reps_for_token(token: str, buf: str, alloc_map: dict, phys_aliases=()):
    """Candidate raw expressions equivalent to a canonical bound token."""
    if token == "PHYS":
        reps = {buf + ".length", "len(" + buf + ")", buf + ".size()",
                buf + ".len()"}
        alloc = alloc_map.get(buf)
        if alloc:
            reps.add(alloc)
        # a length-alias local (`domainLen = buf.length`) is how a binding is
        # usually written: require(count == domainLen).
        for v in phys_aliases:
            reps.add(v)
        return reps
    reps = {token}
    m = _LEN_FN.match(token)
    if m:
        reps.add(m.group(1) + ".length")
    return reps


def _binding_between(text_ns: str, reps_a, reps_b):
    """Search whitespace-stripped text for an equality/inequality relation
    between any rep of A and any rep of B. Returns 'equality'|'inequality'|''."""
    eq = False
    ineq = False
    for a in reps_a:
        ca = _canon(a)
        for b in reps_b:
            cb = _canon(b)
            if ca == cb:
                continue
            for op in ("==", "!="):
                if (ca + op + cb) in text_ns or (cb + op + ca) in text_ns:
                    eq = True
            for op in ("<=", ">=", "<", ">"):
                if (ca + op + cb) in text_ns or (cb + op + ca) in text_ns:
                    ineq = True
    if eq:
        return "equality"
    if ineq:
        return "inequality"
    return ""


# --- per-file scan -----------------------------------------------------------
def scan_file(path: Path, rel: str, file_text: str = None):
    ext = path.suffix.lower()
    if ext not in (".sol", ".go"):
        return []
    if file_text is None:
        try:
            file_text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            return []
    # constant/immutable identifiers declared anywhere in this file - used to
    # classify a loop bound as structural (language-aware, not ALL_CAPS-only).
    declared_consts = _collect_declared_constants(file_text)
    # loops[buf] = list of dicts {bound_raw, canon_bound, fn, line, fn_body}
    loops = {}
    fn_bodies = {}
    fn_alias = {}
    for fname, body, boff in _iter_functions(file_text):
        alias_map, alloc_map = _build_maps(body)
        fn_bodies[fname] = body
        fn_alias[fname] = alias_map
        for var, bound_raw, lbody, hoff in _iter_loops_in_body(body, ext):
            bufs = _indexed_buffers(lbody, var)
            if not bufs:
                continue
            abs_off = boff + hoff
            line = file_text.count("\n", 0, abs_off) + 1
            for buf in bufs:
                nb = _norm_bound(bound_raw, alias_map)
                canon_bound = nb
                if nb == "len(%s)" % buf:
                    canon_bound = "PHYS"
                else:
                    alloc = alloc_map.get(buf)
                    if alloc is not None and (
                            _canon(bound_raw) == alloc
                            or nb == _norm_bound(alloc, alias_map)):
                        canon_bound = "PHYS"
                loops.setdefault(buf, []).append({
                    "bound_raw": _canon(bound_raw),
                    "canon": canon_bound,
                    "fn": fname,
                    "line": line,
                    "alloc": alloc_map.get(buf),
                })

    rows = []
    for buf, entries in sorted(loops.items()):
        if len(entries) < 2:
            continue  # not a shared artifact - only enforcement points are >=2 loops
        canon_tokens = {}
        for e in entries:
            canon_tokens.setdefault(e["canon"], []).append(e)
        distinct = sorted(canon_tokens.keys())
        entries_sorted = sorted(entries, key=lambda e: e["line"])
        fns = []
        for e in entries_sorted:
            if e["fn"] not in fns:
                fns.append(e["fn"])
        pair_scope = "same-function" if len(fns) == 1 else "cross-function"
        decoupled = [t for t in distinct if t != "PHYS"]
        scalar_counts = [t for t in decoupled
                         if _is_scalar_count(t, declared_consts)]
        physical_present = "PHYS" in distinct

        binding = "n/a"
        diverges = False
        # divergence requires >=2 distinct post-fold bounds AND >=1 of them a
        # genuine scalar count (not a sibling array's physical length / literal).
        if len(distinct) >= 2 and scalar_counts:
            # gather text to search for a binding: union of touching fn bodies
            touch_text = "".join(_canon(fn_bodies.get(f, "")) for f in fns)
            alloc_ctx = {}
            for e in entries:
                if e.get("alloc"):
                    alloc_ctx[buf] = e["alloc"]
            # length-alias locals for this buffer across touching fns
            # (`domainLen = buf.length`) - bindings are usually written against
            # the alias, not the raw `.length`.
            phys_aliases = []
            for f in fns:
                for v, arr in fn_alias.get(f, {}).items():
                    if arr == buf and v not in phys_aliases:
                        phys_aliases.append(v)
            binding = ""
            for i in range(len(distinct)):
                for j in range(i + 1, len(distinct)):
                    ra = _reps_for_token(distinct[i], buf, alloc_ctx, phys_aliases)
                    rb = _reps_for_token(distinct[j], buf, alloc_ctx, phys_aliases)
                    b = _binding_between(touch_text, ra, rb)
                    if b == "equality":
                        binding = "equality"
                        break
                    if b == "inequality" and binding != "equality":
                        binding = "inequality-partial"
                if binding == "equality":
                    break
            # an == / != guard tying the two bounds together is a sound
            # cardinality binding -> not a divergence.
            diverges = binding != "equality"
            if not binding:
                binding = "none"

        # LOAD-BEARING FIRE = a SAME-FUNCTION shared-buffer divergence, where both
        # loops share full local/alias/allocation context (the commit-loop +
        # settle-loop-in-one-handler shape). CROSS-FUNCTION divergence is kept as
        # an advisory enumeration lead only (fires=False): a same-named local /
        # named-return / storage field iterated by unrelated functions is too
        # FP-prone to trip the strict gate (RLPWriter out_, channelQueue).
        if diverges:
            lead_kind = ("same-function-divergence"
                         if pair_scope == "same-function"
                         else "cross-function-advisory")
        else:
            lead_kind = "no-divergence"
        fires = diverges and pair_scope == "same-function"

        # A FIRED (same-function) divergence is a real survivor = an OPEN
        # obligation, NOT advisory-green: advisory=False + proof_status='open' so
        # a downstream advisory filter counts it OPEN instead of draining
        # silently to advisory (vacuity-telltale fix). The cross-function /
        # no-divergence enumeration leads (fires==False) stay advisory=True.
        rows.append({
            "capability": _CAPABILITY,
            "class": _CLASS,
            "fires": fires,
            "file": rel,
            "line": entries_sorted[0]["line"],
            "function": "|".join(fns),
            "advisory": not fires,
            "proof_status": "open" if fires else "advisory",
            "auto_credit": False,
            "verdict": "needs-fuzz",
            "buffer": buf,
            "loop_count": len(entries),
            "loop_lines": [e["line"] for e in entries_sorted],
            "distinct_bounds": distinct,
            "decoupled_bounds": decoupled,
            "scalar_counts": scalar_counts,
            "physical_bound_present": physical_present,
            "binding": binding,
            "pair_scope": pair_scope,
            "lead_kind": lead_kind,
        })
    return rows


def scan_tree(root: Path):
    rows = []
    for p in _iter_source_files(root):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            rows.extend(scan_file(p, rel))
        except Exception:
            continue
    return rows


def _emit_sidecar(ws: Path, rows, surface_present: bool = False):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
        # Capability-vacuity-telltale: screen RAN over a real source surface, 0 rows
        # -> PERSIST a cited-empty examined-record (FIRED_CLEAN, not silently VACUOUS).
        if not rows and surface_present:
            fh.write(json.dumps({
                "schema": HYP_SCHEMA,
                "note": ("cited-empty: cross-layer committed-vs-consumed cardinality "
                         "screen ran over the source surface, 0 divergence sites"),
                "survivors": [],
                "report": {"reasoner": "cross-layer-cardinality-divergence-screen",
                           "verdict": "clean-advisory", "totals": {"examined": 1}},
            }) + "\n")
    return out


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "class": _CLASS,
        "enforcement_points": len(rows),
        "fired": len(fired),
        "same_function_fired": sum(
            1 for r in fired if r.get("pair_scope") == "same-function"),
        "cross_function_advisory": sum(
            1 for r in rows if r.get("lead_kind") == "cross-function-advisory"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EXT04 cross-layer committed-vs-consumed cardinality-"
                    "divergence screen (advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(_STRICT_ENV, "").strip() not in (
        "", "0", "false")

    if args.file:
        p = Path(args.file)
        rows = scan_file(p, p.name)
        print(json.dumps(rows, indent=2))
        return 1 if (strict and any(r["fires"] for r in rows)) else 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 1 if (strict and any(r["fires"] for r in rows)) else 0

    if not args.workspace:
        ap.error("one of --workspace / --source / --file is required")

    ws = Path(args.workspace)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / args.workspace
        if cand.exists():
            ws = cand
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines()
                    if l.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["fired"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root)
    surface_present = any(True for _ in _iter_source_files(root))
    _emit_sidecar(ws, rows, surface_present=surface_present)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
