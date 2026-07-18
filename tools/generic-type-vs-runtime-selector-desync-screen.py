#!/usr/bin/env python3
"""generic-type-vs-runtime-selector-desync-screen.py - the GENERIC/PHANTOM-TYPE
vs RUNTIME-SELECTOR DESYNC screen (EXT2-05 / code token EXT2_05).

GENERAL language-intrinsic enforcement-completeness class (never a bug SHAPE). It
instantiates the north-star method ("a TRUSTED ENFORCEMENT is bypassable or its
private invariant is unsound") for a soundness property no wired cap owns: whether
a call that co-supplies a COMPILE-TIME generic/phantom type `<T>` AND a RUNTIME
asset selector (an index / id / coin-type tag / config key / market handle) for the
SAME asset ever proves that the runtime selector resolves to the same asset as
`<T>`.

  ENFORCEMENT POINT : a single function that takes BOTH
      (1) a generic/phantom type param `<T>` USED IN AN ECONOMIC/ASSET position -
          a `Coin<T>` / `Balance<T>` / `Token<T>` / `Supply<T>` wrapper in the
          signature or body (the value that is credited / withdrawn), AND
      (2) a RUNTIME asset SELECTOR value param - an `pool_id` / `market_id` /
          `asset_index` / `coin_type` / `type_tag` / `market_handle` / `Denom` /
          a `*Id` selector type - that NAMES the same asset at run time, AND
      (3) an ASSET-MOVEMENT in the body (withdraw / deposit / split / merge /
          mint / burn / transfer / redeem / ...).
  PRIVATE INVARIANT : the value withdrawn/credited under the runtime selector is
      the SAME asset the generic `T` names - i.e. there is a runtime assertion
      `type_of<T>() == registry[selector].type_tag` (Move: `type_name::get<T>()`;
      Rust: `TypeId::of::<T>()`) coupling the erased type to the dynamic handle.
  ATTACK / DEFECT : the generic is TRUSTED to name the economic asset while the
      selector is attacker-chosen and UNCHECKED. A caller pairs `Pool<A>` with a
      `B`-index so one coin type is withdrawn while another is credited. Type-check
      PASSES (both types are independently valid); the run-time handle diverges.
      Blast radius (asset substitution / theft) is decided at RUN TIME - not here.

Anchor: OpenZeppelin "Critical bug patterns in Sui Move" - a BTC pool combined
with a USDC asset index caused one coin type to be withdrawn while another was
credited. (openzeppelin.com/news/critical-bug-patterns-in-sui-move)

WHY NET-NEW: generics deliver compile-time type-safety but carry NO runtime binding
to a user-supplied selector; the compiler cannot couple a phantom `T` to a dynamic
config index. This type-erased-selector desync passes type-checking yet diverges
when the static type and the runtime handle name different assets. Distinct from
R1 handle-freshness (which STRICTLY requires a recycle/lifecycle event
move_from/Table::remove/destroy + a persisting stale holder - absent here), from
M1 coin-conservation (per-`T` sum(parts)==whole - a BTC->USDC substitution passes),
from M2 discarded-check-result (needs an enforcer OUTPUT to ignore - here there is
no check at all), and from operand-commensurability (numeric BASIS, not asset
IDENTITY). The point is a single call co-supplying `<T>` + an untyped selector with
NO `type_of<T>()==registry[id]` cross-check.

The screen answers, per enforcement point,
  {asset_generic, wrapper, selector, movement, has_type_selector_coupling}
and FIRES (fires=True, verdict='needs-fuzz') ONLY when the coupling is ABSENT.

It BIASES TOWARD SILENCE. A row is emitted only for a function that BOTH uses a
generic in an ASSET-WRAPPER position AND takes an asset-scoped runtime selector AND
performs an asset movement; among those it stays SILENT whenever ANY `type_of`/
`type_name`/`TypeId::of` reflection binds the generic (the coupling fix). A generic
that never wraps a coin, or a selector that is not asset-scoped, never fires.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode; the
opt-in env AUDITOOOR_GENERIC_TYPE_SELECTOR_DESYNC_STRICT (or --strict) only raises
the exit code when a fired point exists.

Languages: Move (.move) + Rust (.rs) - the two surfaces where a compile-time
generic/phantom type co-exists with a runtime asset selector. Silent on every other
tree (Solidity has no generics; Go generics do not carry the phantom-asset shape).

Usage:
  --workspace/--ws <ws>  scan <ws>/src (or <ws>) -> .auditooor/<sidecar>.jsonl + summary
  --source <dir>         scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>             scan a single .move/.rs file, print rows as JSON
  --check                re-read the emitted sidecar, print cert verdict (advisory)
  --strict               (or env) elevate exit code when a fired point exists
  --json                 machine summary to stdout
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

HYP_SCHEMA = "auditooor.generic_type_selector_desync_hypotheses.v1"
_SIDE_NAME = "generic_type_selector_desync_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_GENERIC_TYPE_SELECTOR_DESYNC_STRICT"
_CAPABILITY = "EXT2_05"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmark", "benchmarks", "fuzz", "examples",
              "prior_audits", "reference", "docs", "tests", "test",
              "mocks", "mock", "testdata", "simulation", "simapp",
              "chimera_harnesses", "poc-tests"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|"
    r"fixtures|fuzz|simulation|simapp|chimera_harnesses|poc-tests|"
    r"prior_audits)(/|$)")

# --- machine-generated source exclusion --------------------------------------
# mirrors tools/declared-control-mutator-completeness-screen.py :: _is_generated_source
_GENERATED_SUFFIXES = (
    ".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go", "_generated.go",
    ".pb.rs", "_gen.rs", ".gen.rs", "_generated.rs",
)
_GENERATED_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)
_RUST_GENERATED_SENTINEL = re.compile(
    r"(@generated|Automatically generated|This file (is|was) (auto[- ]?)?generated|"
    r"Generated (by|from) .{0,60}?(prost|tonic|bindgen|protoc))", re.I)


def _is_generated_source(path: Path) -> bool:
    """Path-suffix + header-sentinel codegen classifier (declared-control-mutator
    _is_generated_source parity), extended with the Rust prost/tonic/bindgen
    sentinels."""
    if path.name.lower().endswith(_GENERATED_SUFFIXES):
        return True
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except (OSError, UnicodeError):
        return False
    return bool(_GENERATED_SENTINEL.search(head)
                or _RUST_GENERATED_SENTINEL.search(head))


def _excluded_path(p: Path) -> bool:
    """True when the file is test / mock / sim / chimera / codegen scaffolding and
    must never be scanned. Uses the shared synthetic_target_exclusion predicates AND
    the codegen classifier."""
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
            if not (low.endswith(".move") or low.endswith(".rs")):
                continue
            if low.endswith("_test.rs") or low.endswith("_tests.rs"):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            if _excluded_path(p):
                continue
            yield p


# ---------------------------------------------------------------------------
# Comment / string masker (Rust + Move).
#
# Handles // line comments, /* */ block comments (nestable), "..." strings (with
# \-escapes), and Rust raw strings r"...", r#"..."#. Move byte/hex strings b"..",
# x".." fall through to the normal-string arm. Char literals ('a') are masked but a
# Rust lifetime ('ident, no closer) is left intact. Newlines + per-line length are
# preserved so line indices stay source-accurate. Errs toward SILENCE: a masked span
# can only DROP a would-be token, never invent one.
# ---------------------------------------------------------------------------
_CHAR_LIT_RE = re.compile(r"'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]+\}|.)|[^'\\\n])'")


def _is_raw_string_start(text: str, i: int) -> bool:
    j = i
    if text[j] in ("b", "r") and text[j] == "b":
        j += 1
    if j >= len(text) or text[j] != "r":
        return False
    j += 1
    while j < len(text) and text[j] == "#":
        j += 1
    return j < len(text) and text[j] == '"'


def _consume_raw_string(text: str, i: int):
    n = len(text)
    j = i
    if text[j] == "b":
        j += 1
    j += 1  # skip 'r'
    hashes = 0
    while j < n and text[j] == "#":
        hashes += 1
        j += 1
    j += 1  # skip opening quote
    close = '"' + ("#" * hashes)
    end = text.find(close, j)
    stop = n if end == -1 else end + len(close)
    span = text[i:stop]
    masked = "".join("\n" if ch == "\n" else " " for ch in span)
    return stop, masked


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
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth > 0:
                if text[i] == "/" and i + 1 < n and text[i + 1] == "*":
                    depth += 1
                    out.append("  ")
                    i += 2
                elif text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                else:
                    out.append("\n" if text[i] == "\n" else " ")
                    i += 1
            continue
        if c in ("r", "b") and _is_raw_string_start(text, i):
            i, masked = _consume_raw_string(text, i)
            out.append(masked)
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
        if c == "'":
            m = _CHAR_LIT_RE.match(text, i)
            if m:
                out.append(" " * (m.end() - m.start()))
                i = m.end()
                continue
            out.append(c)  # lifetime - leave intact
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Balanced-delimiter helpers
# ---------------------------------------------------------------------------
def _match_close(text: str, open_idx: int, open_ch: str, close_ch: str):
    depth = 0
    i, n = open_idx, len(text)
    while i < n:
        c = text[i]
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _split_top(text: str):
    """Split on top-level commas (respecting <> () [] {} depth). `->` is an atom."""
    parts, buf = [], []
    pairs = {"<": ">", "(": ")", "[": "]", "{": "}"}
    closers = set(pairs.values())
    stack = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "-" and i + 1 < n and text[i + 1] == ">":
            buf.append("->")
            i += 2
            continue
        if c in pairs:
            stack.append(pairs[c])
            buf.append(c)
        elif c in closers:
            if stack and stack[-1] == c:
                stack.pop()
            buf.append(c)
        elif c == "," and not stack:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    if buf:
        parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _find_top_level(text: str, needle: str):
    depth = 0
    i, n = 0, len(text)
    nl = len(needle)
    while i < n:
        c = text[i]
        if c == "-" and i + 1 < n and text[i + 1] == ">":
            i += 2
            continue
        if c in "<([":
            depth += 1
        elif c in ">)]":
            if depth > 0:
                depth -= 1
        elif depth == 0 and text.startswith(needle, i):
            before = text[i - 1] if i > 0 else " "
            after = text[i + nl] if i + nl < n else " "
            if not (before.isalnum() or before == "_") and \
               not (after.isalnum() or after == "_"):
                return i
        i += 1
    return -1


def _line_of(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _segments(ident: str):
    """Lowercase segments across camelCase + `_` boundaries."""
    segs = []
    for p in re.split(r"[_\W]+", ident or ""):
        for s in re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+", p):
            segs.append(s.lower())
    return segs


def _whole_word_in(g: str, text: str) -> bool:
    return bool(re.search(r"(?<![A-Za-z0-9_])" + re.escape(g) + r"(?![A-Za-z0-9_])",
                          text))


# ---------------------------------------------------------------------------
# Function iteration (Rust `fn` + Move `fun`), masked text
# ---------------------------------------------------------------------------
_MOD = (r"(?:\b(?:pub|public|async|entry|unsafe|native|const|inline|friend|package)"
        r"\b(?:\s*\([^)]*\))?\s+|\bextern\b\s+\"[^\"]*\"\s+)*")
_FN_RE_DECL = re.compile(
    r"(?<![A-Za-z0-9_])(?P<pfx>" + _MOD + r")(?P<kw>fun|fn)\s+(?P<name>[A-Za-z_]\w*)")


def _iter_fns(text: str):
    """Yield (name, is_exposed, sig_text, body_text, decl_offset) for each Rust
    `fn` / Move `fun`. sig_text spans the decl .. the body '{' (exclusive) or the
    trailing ';'. body_text is '' for a bodyless declaration."""
    for m in _FN_RE_DECL.finditer(text):
        name = m.group("name")
        pfx = m.group("pfx") or ""
        is_exposed = ("pub" in pfx) or ("public" in pfx) or ("entry" in pfx)
        i, n = m.end(), len(text)
        adepth = pdepth = bdepth = 0
        sig_end = body_brace = -1
        while i < n:
            c = text[i]
            if c == "-" and i + 1 < n and text[i + 1] == ">":
                i += 2
                continue
            if c == "<":
                adepth += 1
            elif c == ">":
                if adepth > 0:
                    adepth -= 1
            elif c == "(":
                pdepth += 1
            elif c == ")":
                if pdepth > 0:
                    pdepth -= 1
            elif c == "[":
                bdepth += 1
            elif c == "]":
                if bdepth > 0:
                    bdepth -= 1
            elif c == "{" and adepth == pdepth == bdepth == 0:
                body_brace = sig_end = i
                break
            elif c == ";" and adepth == pdepth == bdepth == 0:
                sig_end = i
                break
            i += 1
        if sig_end == -1:
            continue
        sig_text = text[m.start():sig_end]
        if body_brace == -1:
            yield name, is_exposed, sig_text, "", m.start()
            continue
        body_end = _match_close(text, body_brace, "{", "}")
        yield name, is_exposed, sig_text, text[body_brace:body_end], m.start()


def _parse_sig(sig_text: str):
    """Return (generics[(name, is_phantom)], value_params[(name, type)]) for a
    Rust/Move signature. Lifetimes + const generics are dropped; Move `phantom`
    type params are flagged."""
    mm = re.search(r"\b(?:fun|fn)\s+[A-Za-z_]\w*", sig_text)
    rest = sig_text[mm.end():] if mm else sig_text

    generics = []
    lt = rest.find("<")
    paren = rest.find("(")
    after_generics = rest
    if lt != -1 and (paren == -1 or lt < paren):
        gclose = _match_close(rest, lt, "<", ">")
        ginner = rest[lt + 1:gclose - 1]
        for item in _split_top(ginner):
            it = item.strip()
            if it.startswith("'"):          # lifetime param
                continue
            if it.startswith("const "):     # const generic
                continue
            is_phantom = it.startswith("phantom")
            namepart = it.split(":", 1)[0]
            ids = re.findall(r"[A-Za-z_]\w*", namepart)
            # drop the leading `phantom` keyword when present
            ids = [x for x in ids if x != "phantom"]
            if ids:
                generics.append((ids[-1], is_phantom))
        after_generics = rest[gclose:]

    value_params = []
    p_open = after_generics.find("(")
    if p_open != -1:
        p_close = _match_close(after_generics, p_open, "(", ")")
        pinner = after_generics[p_open + 1:p_close - 1]
        for item in _split_top(pinner):
            low = item.strip()
            if re.match(r"^(&\s*)?(mut\s+)?self\b", low):
                continue
            if ":" not in item:
                continue
            nm, _, ty = item.partition(":")
            ids = re.findall(r"[A-Za-z_]\w*", nm)
            if not ids:
                continue
            value_params.append((ids[-1], ty.strip()))
    return generics, value_params


# ---------------------------------------------------------------------------
# (1) asset-generic: a generic used in an ECONOMIC/ASSET wrapper position
# ---------------------------------------------------------------------------
_ASSET_WRAPPER_OPEN = re.compile(
    r"\b(Coin|Balance|Token|FungibleAsset|Fungible|Supply|CoinStore|TreasuryCap|"
    r"MintCap(?:ability)?|BurnCap(?:ability)?|Currency|Reserve|Vault|Pool)\s*<")


def _wrapper_binds_generic(text: str, g: str):
    """Return the wrapper name if some `Wrapper<... g ...>` binds generic `g`, else
    None. `g` must appear as a whole word inside the wrapper's angle args."""
    for m in _ASSET_WRAPPER_OPEN.finditer(text):
        oa = m.end() - 1  # position of '<'
        close = _match_close(text, oa, "<", ">")
        inner = text[oa + 1:close - 1]
        if _whole_word_in(g, inner):
            return m.group(1)
    return None


def _asset_generics(generics, sig_text: str, body_text: str):
    """Yield (generic_name, is_phantom, wrapper) for every generic used in an asset
    wrapper position anywhere in the signature or body."""
    for gname, is_phantom in generics:
        w = _wrapper_binds_generic(sig_text, gname) or \
            _wrapper_binds_generic(body_text, gname)
        if w:
            yield gname, is_phantom, w


# ---------------------------------------------------------------------------
# (2) runtime asset selector param
# ---------------------------------------------------------------------------
_ASSET_NOUN = frozenset({
    "pool", "market", "asset", "coin", "token", "vault", "reserve", "bank",
    "fund", "treasury", "collateral", "synth", "denom", "currency", "instrument",
    "lending", "book", "position"})
_SEL_NOUN = frozenset({
    "id", "ids", "idx", "index", "indices", "key", "keys", "handle", "tag",
    "slot", "type", "no", "num", "name"})
# selector identifiers that are asset-scoped on their own (no separate asset noun)
_STANDALONE_SEL = frozenset({"denom", "coin_type", "cointype", "type_tag",
                             "typetag", "type_name", "typename", "market_handle",
                             "markethandle", "config_key", "configkey"})
_SEL_TYPE_RE = re.compile(
    r"\b(PoolId|MarketId|AssetId|CoinId|CoinType|TokenId|VaultId|ReserveId|"
    r"BankId|FundId|Denom|TypeTag|TypeName|StructTag|ConfigKey|MarketHandle|"
    r"AssetIndex|PoolIndex|CoinIndex|CurrencyId|InstrumentId|BookId|MarketParams|"
    r"PositionId)\b")


def _is_selector_param(name: str, ptype: str):
    """Return a short reason string if the value param is an asset-scoped runtime
    selector, else None. Biases to silence: a bare `id` / `idx` (no asset noun)
    does NOT qualify."""
    low_name = name.lower()
    if low_name in _STANDALONE_SEL:
        return "standalone-selector-name"
    segs = set(_segments(name))
    if (segs & _ASSET_NOUN) and (segs & _SEL_NOUN):
        return "asset-scoped-selector-name"
    if _SEL_TYPE_RE.search(ptype or ""):
        return "selector-type"
    return None


def _selector_params(value_params):
    """Yield (name, type, reason) for each asset-scoped runtime selector param."""
    for nm, ty in value_params:
        reason = _is_selector_param(nm, ty)
        if reason:
            yield nm, ty, reason


# ---------------------------------------------------------------------------
# (3) asset-movement in the body / fn name
# ---------------------------------------------------------------------------
_MOVE_VERB_RE = re.compile(
    r"\b(withdraw|deposit|transfer|mint|burn|split|merge|credit|debit|redeem|"
    r"extract|payout|pay_out|settle|release|claim|unstake|stake|swap|repay|"
    r"collect|distribute|liquidate)\b", re.I)


def _movement(fn_name: str, body_text: str):
    """Return a sorted list of asset-movement verbs found in the fn name / body."""
    found = set()
    for m in _MOVE_VERB_RE.finditer(fn_name):
        found.add(m.group(1).lower())
    for m in _MOVE_VERB_RE.finditer(body_text):
        found.add(m.group(1).lower())
    return sorted(found)


# ---------------------------------------------------------------------------
# THE CORE PREDICATE: does the body couple the generic to the runtime selector?
# ---------------------------------------------------------------------------
# a T-reflection call: type_of<..>, type_name(::get)?<..>, type_name::<..>,
# TypeId::of::<..>, TypeInfo::of, type_info::type_of - the exact constructs used to
# assert `type_of<T>() == registry[id].type_tag`.
_REFLECT_OPEN_RE = re.compile(
    r"\btype_of\s*<|"
    r"\btype_name\s*(?:::\s*get)?\s*<|"
    r"\btype_name\s*::\s*<|"
    r"\bTypeId\s*::\s*of\s*::\s*<|"
    r"\bStructTag\s*::\s*of\s*<")
_REFLECT_BARE_RE = re.compile(
    r"\btype_of\b|\btype_name\b|\bTypeId\s*::\s*of\b|\bTypeInfo\s*::\s*of\b|"
    r"\btype_info\s*::\s*type_of\b|\bStructTag\s*::\s*of\b")


def _reflection_binds_generic(body_text: str, g: str) -> bool:
    """True when a T-reflection call's angle args name generic `g` as a whole word
    (`type_name::get<G>()`, `TypeId::of::<G>()`)."""
    for m in _REFLECT_OPEN_RE.finditer(body_text):
        oa = body_text.find("<", m.start(), m.end())
        if oa == -1:
            continue
        close = _match_close(body_text, oa, "<", ">")
        if _whole_word_in(g, body_text[oa + 1:close - 1]):
            return True
    return False


def _has_type_selector_coupling(body_text: str, asset_generic: str) -> bool:
    """CORE PREDICATE. True when the body couples the generic type to the runtime
    selector - i.e. a `type_of`/`type_name`/`TypeId::of` reflection binds the asset
    generic, OR (silence-biased) any bare type-reflection is present in the body.
    When True the enforcement point is considered SOUND and the screen stays SILENT.
    Neutralizing this to a constant True makes every point silent (the non-vacuity
    hinge); a constant False makes every enumerated point fire."""
    if _reflection_binds_generic(body_text, asset_generic):
        return True
    if _REFLECT_BARE_RE.search(body_text):
        return True
    return False


# ---------------------------------------------------------------------------
# Row construction
# ---------------------------------------------------------------------------
def _stable_id(rel, fn, generic, selector, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{generic}|{selector}|{line}".encode())
    return h.hexdigest()[:16]


def _lang_of(rel: str) -> str:
    return "move" if rel.lower().endswith(".move") else "rust"


def scan_file(path: Path, rel: str, file_text: str = None):
    """Return enforcement-point rows for one .move/.rs file, each with a `fires`
    bool. A point is emitted only when a generic is used in an ASSET-WRAPPER
    position AND the fn takes an asset-scoped runtime selector AND performs an asset
    movement. It FIRES iff no `type_of<T>()==registry[selector]` coupling is present."""
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask(raw)
    lang = _lang_of(rel)
    rows = []
    for name, is_exposed, sig_text, body_text, decl_off in _iter_fns(text):
        if not body_text:
            continue
        generics, value_params = _parse_sig(sig_text)
        if not generics:
            continue
        agens = list(_asset_generics(generics, sig_text, body_text))
        if not agens:
            continue
        selectors = list(_selector_params(value_params))
        if not selectors:
            continue
        verbs = _movement(name, body_text)
        if not verbs:
            continue
        line = _line_of(text, decl_off)
        for gname, is_phantom, wrapper in agens:
            coupled = _has_type_selector_coupling(body_text, gname)
            fires = not coupled
            sel_names = [s[0] for s in selectors]
            sel = selectors[0]
            if fires:
                q = (f"`{name}` co-supplies generic `{gname}` (used as "
                     f"`{wrapper}<{gname}>`) and the runtime selector "
                     f"`{sel[0]}: {sel[1][:40]}` while moving an asset "
                     f"({', '.join(verbs)}), but NOTHING asserts "
                     f"`type_of<{gname}>() == registry[{sel[0]}].type_tag`. "
                     f"Can a caller pair `{wrapper}<A>` with a B-`{sel[0]}` so one "
                     f"asset is withdrawn and another credited (type-erased "
                     f"selector desync, asset substitution)?")
            else:
                q = (f"`{name}` co-supplies generic `{gname}` and runtime selector "
                     f"`{sel[0]}` but a `type_of`/`type_name`/`TypeId::of` reflection "
                     f"binds `{gname}` to the resolved handle - the desync is "
                     f"cross-checked (enforcement point sound; silent).")
            rows.append({
                "schema": HYP_SCHEMA,
                "capability": _CAPABILITY,
                "id": _stable_id(rel, name, gname, sel[0], line),
                "file": rel,
                "line": line,
                "function": name,
                "lang": lang,
                "is_exposed": is_exposed,
                "asset_generic": gname,
                "phantom": is_phantom,
                "asset_wrapper": wrapper,
                "runtime_selector": sel[0],
                "selector_type": sel[1][:60],
                "selector_reason": sel[2],
                "all_selectors": sel_names,
                "movement_verbs": verbs,
                "has_type_selector_coupling": coupled,
                "fires": fires,
                "verdict": "needs-fuzz",
                "advisory": True,
                "auto_credit": False,
                "question": q,
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
    by_lang = {}
    for r in fired:
        by_lang[r.get("lang")] = by_lang.get(r.get("lang"), 0) + 1
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "enforcement_points": len(rows),
        "fired": len(fired),
        "fired_by_lang": by_lang,
        "sound_silent": len(rows) - len(fired),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


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
        description="EXT2-05 generic/phantom-type vs runtime-selector desync screen "
                    "(Move + Rust, advisory)")
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

    ws = _resolve_ws(args.workspace)
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
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
