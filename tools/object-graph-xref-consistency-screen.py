#!/usr/bin/env python3
"""object-graph-xref-consistency-screen.py - the OBJECT-GRAPH CROSS-REFERENCE
CONSISTENCY screen (EXT2-02 / EXT2_02).

GENERAL LOGIC / TRUST-ENFORCEMENT class (never a bug SHAPE). It instantiates the
north-star method ("a TRUSTED ENFORCEMENT is bypassable or its private invariant
is unsound") for one whole-system safety property that NO per-object detector
owns and no type-system / per-argument access-control layer owns:

  DELEGATED-TRUSTED INVARIANT : when an entrypoint accepts TWO OR MORE related
    stateful handles at once (config+state, pool+registry, whitelist+owner,
    market+position, vault+strategy, parent+child, marketParams+id, principal+
    reserves, ...), the caller is trusted to have supplied a handle SET that
    references each other - a must-move-together object graph.
  PRIVATE INVARIANT           : the pairing is EXPLICITLY asserted - one handle's
    field/method back-references the other (`child.parent == parent`,
    `pool.market() == market`, `registry.contains(handle)`, a shared identity
    field such as `principal.denom == reserves.denom`). Individually type-valid +
    individually authorized is NOT enough; the RELATION must be checked.
  ATTACK                      : the cross-reference is UNCHECKED. A type system
    validates each object in isolation; per-argument access-control authorizes
    each object in isolation; neither owns the WHOLE-SYSTEM invariant that the set
    references each other. An attacker substitutes a type-valid but FOREIGN second
    handle to bind their own object into a victim's operation, or graft a victim's
    object into their own (the MoveBit launchpad `invest()` accepted a whitelist
    from a DIFFERENT launchpad; the direct Solidity analogue is an unvalidated
    pool/market/vault parameter, corpus INV-XLANG-GO-0040 `aToken.POOL()==pool`).

Enforcement points = every function that co-passes >=2 RELATED handle-typed
params, both dereferenced (each drives the operation). The screen answers per
point:
  {handle_a, handle_b, related_via, both_dereferenced, has_pair_binding,
   co_passed_handles}
and flags (WARN, verdict=needs-fuzz) ONLY when:
  - both handles are handle-typed (a user-defined struct/interface/resource-id
    type, or an address/bytes32 param whose NAME is a handle noun), AND
  - the two are RELATED (a known pair, container<->member nouns, a cross-name
    member access, or a shared identity FIELD) - i.e. a plausible must-move-
    together set, not two unrelated arguments (token+recipient), AND
  - BOTH are dereferenced in the body (each is actually loaded/used), AND
  - NO relational assertion binds them (no `==`/`!=`/membership guard that
    references both handles) - the pairing is inferred, never checked.

This is DISTINCT from every wired neighbour: coupled-state-completeness tracks
numeric VALUE conservation and DISCARDS config/handle/address fields; guard-
predicate-soundness covers a PRESENT-but-wrong guard, not a MISSING relational
assertion; deferred-execution-param-binding is single-object temporal replay;
the stale-handle SCG arm is temporal identity-recycle of ONE handle, not spatial
pairing of a co-passed SET; per-argument access-control validates one object in
isolation.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode;
the opt-in env AUDITOOOR_OBJECT_GRAPH_XREF_STRICT (or --strict) only raises the
exit code when a fired point exists.

Language-general: Solidity (.sol) and Go (.go). Silent on other trees. Excludes
machine-generated / test / sim / chimera code (shared exclusion libs).

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/object_graph_xref_consistency_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar - tests/verify)
  --file <f>         scan a single .sol/.go file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when an unchecked pairing exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.object_graph_xref_consistency_hypotheses.v1"
_SIDE_NAME = "object_graph_xref_consistency_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_OBJECT_GRAPH_XREF_STRICT"
_CAPABILITY = "EXT2_02"

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# --- shared exclusion (reuse, never rebuild) --------------------------------
try:  # tools/lib/synthetic_target_exclusion.py
    from lib.synthetic_target_exclusion import (  # noqa: E402
        is_chimera_mutation_harness_path,
        is_codegen_path,
        is_test_target_path,
    )
except Exception:  # pragma: no cover - degrade to no-op if lib unavailable
    def is_test_target_path(_p):  # type: ignore
        return False

    def is_codegen_path(_p, workspace=None):  # type: ignore
        return False

    def is_chimera_mutation_harness_path(_p):  # type: ignore
        return False


def _load_declared_control_is_generated():
    """Reuse tools/declared-control-mutator-completeness-screen.py::
    _is_generated_source (the .go/.sol codegen sentinel screen) rather than
    re-inline it. The module filename is hyphenated so it is loaded by path."""
    tool = TOOLS_DIR / "declared-control-mutator-completeness-screen.py"
    try:
        spec = importlib.util.spec_from_file_location("_dc_screen", tool)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        return mod._is_generated_source
    except Exception:  # pragma: no cover
        _SUF = (".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go",
                "_generated.go")
        _SENT = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)

        def _fallback(path: Path) -> bool:
            if path.name.lower().endswith(_SUF):
                return True
            try:
                return bool(_SENT.search(
                    path.read_text(encoding="utf-8", errors="replace")[:4096]))
            except OSError:
                return False
        return _fallback


_is_generated_source = _load_declared_control_is_generated()

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "certora", "simulation", "simapp"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|"
    r"fixtures|simulation|simapp)(/|$)")


# ============================================================================
# lexicons
# ============================================================================
# A stateful graph handle is denoted by these nouns (used to (a) accept an
# address/bytes32 param as a handle, and (b) classify container vs member and
# the relatedness of two co-passed handles). Segment-based, lowercased.
_CONTAINER_NOUNS = {
    "registry", "whitelist", "allowlist", "blocklist", "blacklist", "launchpad",
    "factory", "controller", "manager", "config", "configuration", "market",
    "marketparams", "pool", "vault", "collection", "gauge", "parent",
    "safe", "oracle", "reserves", "reserve", "treasury", "bank", "book",
    "ledger", "silo", "morpho",
}
# NB: `owner` is deliberately NOT a generic container noun (an owner is an
# authority/account, not a graph container of the second handle) - it relates
# only through the explicit (whitelist, owner) lexicon pair. This kills the
# createVaultV2(owner, asset) style FP.
_MEMBER_NOUNS = {
    "position", "pair", "strategy", "child", "adapter", "plugin", "hook",
    "account", "token", "asset", "collateral", "id", "params", "order", "loan",
    "tranche", "stream", "campaign", "principal", "module", "escrow",
    "whitelist", "coin", "denom",
}
_HANDLE_NOUNS = _CONTAINER_NOUNS | _MEMBER_NOUNS

# Known must-move-together pairs (unordered noun sets). A pair is related when one
# handle contributes one noun and the other handle contributes the other.
_RELATED_PAIRS = [
    frozenset(p) for p in (
        ("pool", "registry"), ("pool", "market"), ("market", "position"),
        ("vault", "strategy"), ("vault", "adapter"), ("parent", "child"),
        ("whitelist", "owner"), ("launchpad", "whitelist"),
        ("collection", "pair"), ("gauge", "pool"), ("safe", "module"),
        ("config", "adapter"), ("principal", "reserves"),
        ("principal", "vault"), ("market", "id"), ("marketparams", "id"),
        ("position", "market"), ("adapter", "registry"), ("account", "token"),
        ("collateral", "market"), ("vault", "market"),
        ("oracle", "market"), ("morpho", "market"),
    )
]

# membership / containment / back-reference guard tokens (a pairing assertion
# need not use `==`; `registry.contains(pool)` binds by membership).
_MEMBERSHIP_TOKENS = (
    "contains", "contain", "has", "includes", "include", "ismember", "member",
    "registered", "isregistered", "whitelisted", "iswhitelisted", "allowed",
    "isallowed", "exists", "isvalid", "belongs", "belongsto", "ownerof",
    "parentof", "lookup", "isknown", "known",
)

_RELOP_RE = re.compile(r"(==|!=|<=|>=|<|>)")

# Solidity value (non-handle) base types.
_SOL_VALUE_EXACT = {"bool", "string", "byte"}
_SOL_VALUE_RE = re.compile(r"^(uint\d*|int\d*|bytes\d*|bool|string|byte)$")
# address / bytes32 / uint256 become a handle ONLY when the NAME is a handle noun.
_SOL_NAME_GATED = {"address", "bytes32", "uint256", "uint", "bytes"}

# Go builtins + qualified value/ctx types that are NOT graph handles.
_GO_BUILTINS = {
    "string", "bool", "int", "int8", "int16", "int32", "int64", "uint",
    "uint8", "uint16", "uint32", "uint64", "byte", "rune", "error", "float32",
    "float64", "complex64", "complex128", "uintptr", "any", "bytes",
}
_GO_NONHANDLE_TYPES = {
    "Context", "Error", "Int", "Uint", "Dec", "LegacyDec", "BigInt", "Rat",
    "Time", "Duration", "Buffer", "Reader", "Writer", "Hash", "Bytes",
    "String", "Bool", "Uint64", "Int64", "T",
}

_LOC_KW = {"memory", "calldata", "storage", "indexed", "payable"}


# ============================================================================
# comment/string masking + function extraction (Solidity + Go)
# ============================================================================
def _mask_comments(text: str) -> str:
    """Blank // and /* */ comments and string literals, preserving newlines / line
    length so indices stay source-accurate. Errs toward SILENCE."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = False
    quote = ""
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                in_block = False
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif in_str:
            out.append(" ")
            if c == "\\":
                out.append(" ")
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
        elif c in ('"', "'", "`"):
            in_str = True
            quote = c
            out.append(" ")
            i += 1
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


_FN_DECL_RE = re.compile(
    r"^\s*(?:"
    r"function\s+([A-Za-z_]\w*)"                 # Solidity function foo
    r"|(constructor)\b"                          # Solidity constructor
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"   # Go func (recv) Foo / func Foo
    r")")


def _fn_name(m):
    return m.group(1) or m.group(2) or m.group(3)


def _functions(lines):
    """Yield (name, decl_idx, sig_text, body_lines) for each brace-matched fn.
    body_lines is a list of (abs_idx, line) covering signature -> closing brace."""
    i, n = 0, len(lines)
    while i < n:
        m = _FN_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = _fn_name(m) or "<anon>"
        depth = 0
        started = False
        body = []
        sig_parts = []
        j = i
        seen_brace = False
        while j < n:
            line = lines[j]
            if not seen_brace:
                sig_parts.append(line)
                if "{" in line:
                    seen_brace = True
            depth += line.count("{") - line.count("}")
            body.append((j, line))
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
            j += 1
        yield name, i, "\n".join(sig_parts), body
        i = max(j, i + 1)


# ============================================================================
# parameter-list extraction
# ============================================================================
def _matching_paren(s: str, open_idx: int) -> int:
    """Index just past the ')' matching s[open_idx]=='('. len(s) if unbalanced."""
    depth = 0
    for k in range(open_idx, len(s)):
        if s[k] == "(":
            depth += 1
        elif s[k] == ")":
            depth -= 1
            if depth == 0:
                return k + 1
    return len(s)


def _param_str(sig_text: str, lang: str) -> str:
    """Return the raw parameter-list text (contents of the param parens)."""
    s = sig_text
    if lang == "go":
        m = re.search(r"\bfunc\b", s)
        i = m.end() if m else 0
        while i < len(s) and s[i] in " \t\n":
            i += 1
        if i < len(s) and s[i] == "(":          # receiver group -> skip it
            i = _matching_paren(s, i)
        j = s.find("(", i)
        if j < 0:
            return ""
        return s[j + 1:_matching_paren(s, j) - 1]
    # Solidity: first paren after the declaration keyword
    j = s.find("(")
    if j < 0:
        return ""
    return s[j + 1:_matching_paren(s, j) - 1]


def _split_top_commas(param_str: str):
    """Split on top-level commas, respecting () [] {} <> nesting."""
    out, depth, cur = [], 0, []
    for ch in param_str:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return [c.strip() for c in out if c.strip()]


def _parse_params_sol(param_str: str):
    """Yield (name, type) for Solidity params. Unnamed params are skipped."""
    for chunk in _split_top_commas(param_str):
        if "mapping" in chunk or "function" in chunk:
            continue
        toks = [t for t in chunk.split() if t not in _LOC_KW]
        if len(toks) < 2:
            continue                    # type-only / unnamed
        yield toks[-1], toks[0]


def _parse_params_go(param_str: str):
    """Yield (name, type) for Go params, resolving grouped names (`a, b Type`)."""
    pending = []
    for chunk in _split_top_commas(param_str):
        parts = chunk.split(None, 1)
        if len(parts) == 2 and not parts[0].startswith("..."):
            name, typ = parts[0], parts[1].strip()
            for pn in pending:
                yield pn, typ
            pending = []
            yield name, typ
        else:
            pending.append(chunk.strip())
    # trailing pending with no type -> an all-unnamed signature; discard.


def _type_base(typ: str, lang: str) -> str:
    """Reduce a type to its core identifier (`*sdk.Coin`->Coin, `IPool[]`->IPool,
    `MarketParams memory`->MarketParams)."""
    t = typ.strip()
    t = t.split("memory")[0].split("calldata")[0].split("storage")[0].strip()
    t = t.lstrip("*&").strip()
    t = re.sub(r"\[.*$", "", t)          # drop array / slice / index
    if "." in t:
        t = t.split(".")[-1]            # qualified pkg.Type -> Type
    m = re.match(r"[A-Za-z_]\w*", t)
    return m.group(0) if m else ""


def _segments(name: str):
    """camelCase / snake_case -> lowercased segments (+ the whole token)."""
    s = re.sub(r"_", " ", name)
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", s)
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", s)
    segs = [w.lower() for w in s.split() if w]
    whole = re.sub(r"[^A-Za-z0-9]", "", name).lower()
    if whole:
        segs.append(whole)
    return segs


def _handle_nouns(name: str, typ: str, lang: str):
    base = _type_base(typ, lang)
    return set(_segments(name)) | set(_segments(base))


def _is_handle_param(name: str, typ: str, lang: str) -> bool:
    base = _type_base(typ, lang)
    if not base:
        return False
    nouns = _handle_nouns(name, typ, lang)
    if lang == "solidity":
        low = base.lower()
        if _SOL_VALUE_RE.match(low) or low in _SOL_VALUE_EXACT:
            if low in _SOL_NAME_GATED or base == "address":
                return bool(nouns & _HANDLE_NOUNS)
            return False
        # user-defined type (interface / struct / value-type alias like `Id`)
        return True
    # Go
    if base.lower() in _GO_BUILTINS:
        return False
    if not base[0].isupper():
        return False
    if base in _GO_NONHANDLE_TYPES:
        return False
    if name.lower() in ("ctx", "context", "err", "error"):
        return False
    return True


# ============================================================================
# body dereference / relatedness / binding analysis
# ============================================================================
def _body_code(body_lines) -> str:
    """The executable body AFTER the signature's opening brace (drops the
    parameter declaration so param names in the signature are not mistaken for
    dereferences or bindings)."""
    joined = "\n".join(l for _i, l in body_lines)
    brace = joined.find("{")
    return joined[brace + 1:] if brace >= 0 else joined


def _member_accesses(h: str, body: str):
    """(all_members, field_members): identifiers X in `h.X`, `(h).X` (Solidity
    cast `IX(h).X`). field_members excludes X immediately followed by `(` (a
    method CALL) - identity pairing reads FIELDS, not action methods."""
    all_m, fields = set(), set()
    he = re.escape(h)
    for pat in (rf"\b{he}\s*\.\s*([A-Za-z_]\w*)",
                rf"\(\s*{he}\s*\)\s*\.\s*([A-Za-z_]\w*)"):
        for m in re.finditer(pat, body):
            name = m.group(1)
            all_m.add(name)
            after = body[m.end():m.end() + 1]
            if after != "(":
                fields.add(name)
    return all_m, fields


def _is_dereferenced(h: str, body: str, members) -> bool:
    if members:
        return True
    he = re.escape(h)
    if re.search(rf"\[\s*{he}\s*\]", body):      # used as mapping key
        return True
    if re.search(rf"\b{he}\s*\[", body):         # indexed h[...]
        return True
    return False


def has_pair_binding(body: str, a_name: str, b_name: str) -> bool:
    """CORE PREDICATE. True iff some statement RELATIONALLY binds the two handles:
    a single line that references BOTH handles AND is a comparison (==/!=/<>...)
    or a membership/containment guard (`registry.contains(pool)`). Its ABSENCE on
    a co-passed related set is the unchecked-cross-reference violation.

    Neutralizing this predicate (monkeypatch to constant True) makes every planted
    positive STOP firing - proof it is load-bearing, not decoration."""
    ae, be = re.escape(a_name), re.escape(b_name)
    ra = re.compile(rf"\b{ae}\b")
    rb = re.compile(rf"\b{be}\b")
    for line in body.split("\n"):
        if not (ra.search(line) and rb.search(line)):
            continue
        if _RELOP_RE.search(line):
            return True
        low = line.lower()
        if any(re.search(rf"\b{tok}\s*\(", low) or re.search(rf"\.\s*{tok}\b", low)
               for tok in _MEMBERSHIP_TOKENS):
            return True
    return False


def _relatedness(a, b):
    """Return a relatedness tag for two handle params, else None. a/b are dicts
    with name/type/nouns/members(all)/fields."""
    na, nb = a["nouns"], b["nouns"]
    # R1: a known must-move-together pair (each side contributes a DISTINCT noun,
    # so one handle cannot self-match).
    for pair in _RELATED_PAIRS:
        pa, pb = na & pair, nb & pair
        if pa and pb and pa != pb:
            return "lexicon-pair"
    # R2: container <-> member nouns (registry+pool, launchpad+whitelist, ...)
    if ((na & _CONTAINER_NOUNS and nb & _MEMBER_NOUNS)
            or (nb & _CONTAINER_NOUNS and na & _MEMBER_NOUNS)):
        return "container-member"
    # R2b: cross-name member access - a reads a member that names b (or vice versa)
    a_mem_nouns = set()
    for mm in a["members"]:
        a_mem_nouns |= set(_segments(mm))
    b_mem_nouns = set()
    for mm in b["members"]:
        b_mem_nouns |= set(_segments(mm))
    if (a_mem_nouns & (nb - {"id", "params"})) or (b_mem_nouns & (na - {"id", "params"})):
        return "cross-name"
    # R3: a shared IDENTITY field (both read the same field, e.g. `.denom`,`.id`).
    shared = a["fields"] & b["fields"]
    if shared:
        return "shared-field:" + sorted(shared)[0]
    return None


# ============================================================================
# scan
# ============================================================================
def _stable_id(rel, fn, a, b, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{a}|{b}|{line}".encode())
    return h.hexdigest()[:16]


_INIT_NAME_RE = re.compile(r"^(constructor|__init)", re.I)


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lang = "go" if rel.lower().endswith(".go") else "solidity"
    lines = text.split("\n")

    rows = []
    for name, decl_idx, sig, body_lines in _functions(lines):
        param_str = _param_str(sig, lang)
        if not param_str:
            continue
        raw_params = (_parse_params_go(param_str) if lang == "go"
                      else _parse_params_sol(param_str))
        # keep handle-typed params, de-duplicated by name
        handles, seen = [], set()
        for pname, ptype in raw_params:
            if pname in seen:
                continue
            if _is_handle_param(pname, ptype, lang):
                seen.add(pname)
                handles.append((pname, ptype))
        if len(handles) < 2:
            continue

        body = _body_code(body_lines)
        info = {}
        for pname, ptype in handles:
            allm, fields = _member_accesses(pname, body)
            info[pname] = {
                "name": pname, "type": ptype,
                "nouns": _handle_nouns(pname, ptype, lang),
                "members": allm, "fields": fields,
                "deref": _is_dereferenced(pname, body, allm),
            }
        co_passed = [h[0] for h in handles]

        # enumerate unordered related pairs of DEREFERENCED handles
        emitted_pairs = set()
        for ii in range(len(handles)):
            for jj in range(ii + 1, len(handles)):
                a, b = info[handles[ii][0]], info[handles[jj][0]]
                if not (a["deref"] and b["deref"]):
                    continue
                related = _relatedness(a, b)
                if not related:
                    continue
                key = tuple(sorted((a["name"], b["name"])))
                if key in emitted_pairs:
                    continue
                emitted_pairs.add(key)
                bound = has_pair_binding(body, a["name"], b["name"])
                fires = not bound
                rows.append(_row(
                    rel, name, decl_idx, lang, a, b, related, bound,
                    co_passed, fires))
    return rows


def _row(rel, fn, decl_idx, lang, a, b, related, bound, co_passed, fires):
    q = (f"`{fn}` co-passes related handles `{a['name']}`:{a['type']} and "
         f"`{b['name']}`:{b['type']} (related via {related}); each is "
         f"individually type-valid but NO relational assertion binds them "
         f"(no `==`/membership guard references both). Can an attacker supply a "
         f"type-valid but FOREIGN `{b['name']}` that does not belong to "
         f"`{a['name']}` to bind their object into a victim's operation, or graft "
         f"a victim's object into their own?")
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, fn, a["name"], b["name"], decl_idx),
        "file": rel,
        "line": decl_idx + 1,
        "function": fn,
        "lang": lang,
        "handle_a": {"name": a["name"], "type": a["type"]},
        "handle_b": {"name": b["name"], "type": b["type"]},
        "related_via": related,
        "both_dereferenced": True,
        "has_pair_binding": bound,
        "co_passed_handles": co_passed,
        "is_init_fn": bool(_INIT_NAME_RE.match(fn)),
        "fires": fires,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
        "question": q,
    }


def _iter_source_files(root: Path, workspace: Path = None):
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
            rel = str(p)
            # shared exclusion libs: test / chimera / codegen
            if (is_test_target_path(rel) or is_chimera_mutation_harness_path(rel)
                    or is_codegen_path(rel, workspace)):
                continue
            if _is_generated_source(p):
                continue
            yield p


def scan_tree(root: Path, workspace: Path = None):
    rows = []
    for p in _iter_source_files(root, workspace):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            rows.extend(scan_file(p, rel))
        except Exception:
            continue
    return rows


def _emit_sidecar(ws: Path, rows):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return out


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "enforcement_points": len(rows),
        "fired": len(fired),
        "bound_silent": sum(1 for r in rows if r.get("has_pair_binding")),
        "by_relatedness": _count(rows, "related_via"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def _count(rows, key):
    out = {}
    for r in rows:
        v = str(r.get(key, "")).split(":")[0]
        out[v] = out.get(v, 0) + 1
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EXT2-02 object-graph cross-reference consistency screen "
                    "(advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(
        _STRICT_ENV, "").strip() not in ("", "0", "false")

    if args.file:
        p = Path(args.file)
        rows = scan_file(p, p.name)
        print(json.dumps(rows, indent=2))
        return 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 0

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
    rows = scan_tree(root, workspace=ws)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
