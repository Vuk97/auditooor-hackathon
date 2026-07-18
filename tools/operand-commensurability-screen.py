#!/usr/bin/env python3
"""operand-commensurability-screen.py - the OPERAND-COMMENSURABILITY screen (MQ-C02).

GENERAL value-representation / trust-enforcement class (never a bug SHAPE). It
instantiates the north-star method ("a TRUSTED ENFORCEMENT is bypassable or its
private invariant is unsound") for one delegated-and-trusted safety property no
existing screen reaches: whether the two operands a comparison / sum / subtraction
TRUSTS to be commensurable are actually in the SAME accounting basis.

  DELEGATED-TRUSTED INVARIANT : a binary relation over two quantities - a bound
    check `a <= cap`, an equality `x == y`, a value-conservation `out = pool - fee`
    - is trusted to be MEANINGFUL: the two operands are the same KIND of number, so
    the ordering / equality / difference reflects a real economic fact.
  PRIVATE INVARIANT           : that trust holds ONLY if BOTH operands are expressed
    in the SAME accounting basis. A basis is an axis-value the value carries by
    construction:
      * SHARE  : vault SHARES vs underlying ASSETS (one went through
        convertToAssets / toShares / previewRedeem / ... , the other did not);
      * SCALE  : ray / index-SCALED (1e27, `scaledBalanceOf`, a `scaled*` amount)
        vs RAW principal (the scaled value must be `rayMul(index)`-converted first);
      * FEE    : pre-fee GROSS vs post-fee NET;
      * REBASE : an external rebasing `balanceOf()` vs a static internal-accounting
        balance.
  ATTACK / DEFECT ON THE INVARIANT : when the two operands are in DIFFERENT bases,
    the comparison silently conserves NOTHING - a shares amount compared to an
    assets cap, a scaled balance compared to a raw amount, a gross value equated to
    a net one. The blast radius is decided at RUN TIME (a bound is under/over-
    enforced, an equality never/always holds, a conservation drifts), not here.

This is a GENERAL invariant CLASS, not a bug shape:
  - It enumerates the WHOLE binary-relation family (every comparison / sum /
    subtraction whose two operands are both non-trivial values) and asks ONE
    enforcement-completeness question of each: "are these two operands proven to be
    in the SAME accounting basis, or does a basis divergence pass the relation while
    conserving nothing?"
  - The IMPACT is left OPEN (verdict=needs-fuzz). Nothing here decides a tier.

Why the predicate is non-vacuous (see the tests):
  * HALF 1 `_basis` - infer each operand's basis on each axis (from the conversion
    it passed through + its naming + its scale). Neutralize it (every operand
    basis-unknown) and every row disappears.
  * HALF 2 divergence-join - a row is emitted ONLY when, on some axis, BOTH operands
    carry a CONFIDENT and OPPOSITE basis. Neutralize it (pretend the two are always
    the same basis) and every row disappears.

It BIASES TOWARD SILENCE. A row fires ONLY when BOTH operands are confidently
labelled on the SAME axis with OPPOSITE values; an operand with an unknown /
ambiguous basis never fires. That is deliberate - a precise screen, not an
enumerator: the basis tokens (shares / assets / scaled / gross / net) are specific,
and requiring a confident opposite on the OTHER operand keeps the fire rate near
zero on a large workspace.

ADVISORY-FIRST: every emitted row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode. The
strict env AUDITOOOR_OPERAND_COMMENSURABILITY_STRICT (opt-in, or --strict) only
raises the exit code; it still emits no credit. Solidity-only (.sol); silent on
every other tree.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/operand_commensurability_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir (test / ad-hoc), print candidate rows as JSON
  --file <f>         scan a single .sol file, print candidate rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a basis divergence exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.operand_commensurability_hypotheses.v1"
CAPABILITY = "MQ-C02-operand-commensurability"
_SIDE_NAME = "operand_commensurability_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_OPERAND_COMMENSURABILITY_STRICT"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "forge-std", "mocks", "testdata", "certora", "audits",
              "prior_audits", "chimera_harnesses", "poc-tests", "reference"}
# test / mock / example trees are excluded: a comparison there is not a production
# trust surface (harnesses feed synthetic, already-consistent values).
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|example|examples|script|scripts|"
    r"chimera_harnesses|poc-tests|certora|audits|prior_audits)(/|$)", re.IGNORECASE)
_TEST_FILE_HINT = re.compile(r"(\.t\.sol$|\.s\.sol$|Mock|Harness|Test|PoC)")


# --- comment + string masking -------------------------------------------------
def _mask(text: str) -> str:
    """Replace `//` line, `/* */` block comments and string literals with spaces,
    preserving newlines and per-line length so offsets stay source-aligned. Not
    firing on a basis word that only appears inside a comment / string is the point:
    over-masking a token errs toward SILENCE (can only drop a would-be token, never
    invent one)."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = False
    in_str = None  # '"' or "'"
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
        elif in_str is not None:
            if c == "\\":
                out.append("  ")
                i += 2
                continue
            if c == in_str:
                in_str = None
            out.append("\n" if c == "\n" else " ")
            i += 1
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
        elif c == '"' or c == "'":
            in_str = c
            out.append(" ")
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _iter_source_files(root: Path):
    root_str = str(root)
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        # match the test/audit hint on the path RELATIVE to root - an absolute prefix
        # like `/Users/wolf/audits/` must not itself trip the `audits` hint.
        rp = dp[len(root_str):].replace(os.sep, "/")
        if _TEST_HINT.search(rp):
            continue
        for f in fn:
            if not f.endswith(".sol"):
                continue
            if _TEST_FILE_HINT.search(f):
                continue
            yield Path(dp) / f


def _split_segments(ident: str):
    """Split an identifier into lowercase segments across camelCase + `_` boundaries
    (`userShares` -> ['user','shares'], `total_assets` -> ['total','assets'])."""
    parts = re.split(r"[_\W]+", ident)
    segs = []
    for p in parts:
        for s in re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+", p):
            segs.append(s.lower())
    return segs


# --- accounting-basis token / conversion vocabulary ---------------------------
# SHARE axis: a conversion CALL is authoritative (the call name decides the RESULT
# basis, ignoring the arg). If no conversion call, the operand's own naming decides.
_TO_SHARES_CALL = re.compile(
    r"\b(?:convertToShares|toShares(?:Up|Down)?|previewDeposit|previewWithdraw)\s*\(")
_TO_ASSETS_CALL = re.compile(
    r"\b(?:convertToAssets|toAssets(?:Up|Down)?|previewRedeem|previewMint)\s*\(")
_SEG_SHARES = frozenset({"shares", "share"})
_SEG_ASSETS = frozenset({"assets", "asset"})

# SCALE axis: a `scaled*` amount / scaledBalanceOf / a `scaled` segment is a
# ray-index-scaled value; it is only commensurable with a RAW amount after a
# `rayMul`/`rayDiv` (WadRayMath) conversion. A raw amount is one carrying a raw /
# underlying / principal / cap token or a `10 ** decimals` power, or a rayMul result.
_SCALED_TOKEN = re.compile(r"\bscaled[A-Za-z0-9_]*|\bscaledBalanceOf\b")
_RAY_CONV = re.compile(r"\bray(?:Mul|Div)\b|\.ray(?:Mul|Div)\s*\(|WadRayMath")
_SEG_SCALED = frozenset({"scaled"})
_SEG_RAW = frozenset({"raw", "underlying", "principal", "notional", "cap",
                      "supplycap", "borrowcap"})
_DEC_POW = re.compile(r"10\s*\*\*|\b1e\d")

# FEE axis: pre-fee gross vs post-fee net (naming only - a symmetric positive pair).
_SEG_GROSS = frozenset({"gross"})
_SEG_NET = frozenset({"net"})

# REBASE axis: an external rebasing balanceOf() vs a static internal-accounting
# balance (naming only on the static side).
_BALANCEOF = re.compile(r"\bbalanceOf\s*\(")
_SEG_STATIC = frozenset({"internal", "stored", "tracked", "accounted",
                         "recorded", "booked", "shadow"})

# function-unit starts
_FN = re.compile(r"\b(?:function\s+([A-Za-z_]\w*)|(constructor)\b|(receive)\s*\(|"
                 r"(fallback)\s*\()")


def _strip_call_args(text):
    """Remove the CONTENTS of call-argument parens - a `(` immediately preceded
    (ignoring whitespace) by an identifier char or `.` is a function CALL, and its
    args do NOT determine the operand's result basis (`maxWithdraw(isSharesLockup)`
    returns assets, not shares; the `shares` in the arg is noise). Grouping parens
    `... * (10 ** dec)` are KEPT (they carry the operand's own scaling). This kills
    the arg-name-pollution false positive on naming inference; the authoritative
    conversion-call and rayMul detectors still run on the full text."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "(":
            j = len(out) - 1
            while j >= 0 and out[j] in " \t":
                j -= 1
            is_call = j >= 0 and (out[j].isalnum() or out[j] in "_.")
            if is_call:
                # skip balanced call args
                depth, k = 0, i
                while k < n:
                    if text[k] == "(":
                        depth += 1
                    elif text[k] == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    k += 1
                out.append("()")
                i = k + 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _seg_hits(text, seg_set):
    return any(s in seg_set for s in _split_segments(text or ""))


def _single(cands):
    """Collapse a candidate set to a single confident label, or None if empty /
    ambiguous (both labels present -> the operand is NOT confidently one basis)."""
    cs = set(c for c in cands if c)
    return next(iter(cs)) if len(cs) == 1 else None


def _two_token_label(text, set_a, label_a, set_b, label_b):
    """Confident label for a SYMMETRIC two-token axis (shares/assets, gross/net).

    Three-way disambiguation that kills the two false-positive classes seen on the
    real fleet:
      * BOTH tokens appear anywhere (args included) -> the operand is a COMPOUND /
        RATIO (`assets.rDivUp(shares)` is a price, not assets) -> ambiguous -> None.
      * exactly one token appears at the RECEIVER/name level (call args stripped) ->
        that is the operand's basis.
      * a token appears ONLY inside a call's ARGS (`maxWithdraw(isSharesLockup)`
        returns assets, the `shares` is a noise arg) -> unknown -> None.
    """
    a_full = _seg_hits(text, set_a)
    b_full = _seg_hits(text, set_b)
    if a_full and b_full:
        return None
    named = _strip_call_args(text)
    a_named = _seg_hits(named, set_a)
    b_named = _seg_hits(named, set_b)
    if a_named and not b_named:
        return label_a
    if b_named and not a_named:
        return label_b
    return None


def _share_label(text):
    # a conversion call is authoritative for the result basis (ignore the arg tokens)
    has_s = bool(_TO_SHARES_CALL.search(text))
    has_a = bool(_TO_ASSETS_CALL.search(text))
    if has_s or has_a:
        return _single({"shares" if has_s else None, "assets" if has_a else None})
    return _two_token_label(text, _SEG_SHARES, "shares", _SEG_ASSETS, "assets")


def _scale_label(text):
    ray_conv = bool(_RAY_CONV.search(text))
    named = _strip_call_args(text)
    scaled_tok = bool(_SCALED_TOKEN.search(named)) or _seg_hits(named, _SEG_SCALED)
    raw_tok = _seg_hits(named, _SEG_RAW) or bool(_DEC_POW.search(named))
    # an UNCONVERTED scaled value is `scaled`; a converted one (rayMul) is `raw`
    if scaled_tok and not ray_conv:
        return "scaled"
    if ray_conv or raw_tok:
        return "raw"
    return None


def _fee_label(text):
    return _two_token_label(text, _SEG_GROSS, "gross", _SEG_NET, "net")


def _rebase_label(text):
    if _BALANCEOF.search(text):
        return "rebasing"
    if _seg_hits(_strip_call_args(text), _SEG_STATIC):
        return "static"
    return None


_AXES = (
    ("SHARE", _share_label, ("shares", "assets")),
    ("SCALE", _scale_label, ("scaled", "raw")),
    ("FEE", _fee_label, ("gross", "net")),
    ("REBASE", _rebase_label, ("rebasing", "static")),
)

_SIMPLE_ID = re.compile(r"^[A-Za-z_]\w*$")
_ASSIGN_RE_CACHE = {}


def _provenance_rhs(ident, body_text):
    """One-hop provenance: the defining RHS of a simple local identifier (`uint256
    owed = convertToAssets(x);` -> `convertToAssets(x)`). Advisory single hop - errs
    toward SILENCE. Returns the RHS text or None."""
    pat = _ASSIGN_RE_CACHE.get(ident)
    if pat is None:
        pat = re.compile(r"\b" + re.escape(ident) + r"\s*=(?!=)\s*([^;]+);")
        _ASSIGN_RE_CACHE[ident] = pat
    m = pat.search(body_text)
    return m.group(1) if m else None


def _basis(text, body_text):
    """Infer the confident basis label of an operand on each axis. Uses the operand
    text (conversion call + naming + scale) and, for a bare simple identifier with no
    label on an axis, one hop through its defining RHS."""
    labels = {}
    rhs = None
    is_simple = bool(_SIMPLE_ID.match(text.strip()))
    for axis, fn, _ in _AXES:
        lab = fn(text)
        if lab is None and is_simple:
            if rhs is None and body_text is not None:
                rhs = _provenance_rhs(text.strip(), body_text) or ""
            if rhs:
                lab = fn(rhs)
        if lab is not None:
            labels[axis] = lab
    return labels


def _nontrivial(text):
    """An operand is a candidate only if it references a value (an identifier) and is
    not a pure literal / a `type(...)` / an address(0). Pure literals carry no basis
    and are dropped up front (they can never fire, and skipping keeps rows quiet)."""
    t = text.strip()
    if not t:
        return False
    if not re.search(r"[A-Za-z_]\w*", t):
        return False
    if re.fullmatch(r"[-+]?\s*(0x[0-9a-fA-F]+|\d[\d_]*(?:\s*\*\*\s*\d+)?|address\(0\)|"
                    r"type\([^)]*\)\.\w+)", t):
        return False
    if len(t) > 240:
        return False
    return True


# --- binary-op site extraction -------------------------------------------------
_COMP = re.compile(r"(?P<op><=|>=|==|!=|(?<![<])<(?![<=])|(?<![-=>])>(?![>=]))")
_ARITH = re.compile(r"(?<![+\-*/<>=!])(?P<op>[+\-])(?![+\-=>])")
_BOUND_COMMON = set(";{},?&|=!")


def _operand_left(s, start, stop_arith):
    i = start - 1
    while i >= 0 and s[i] in " \t\n":
        i -= 1
    depth, end = 0, i
    while i >= 0:
        c = s[i]
        if c in ")]":
            depth += 1
        elif c in "([":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0:
            if c in _BOUND_COMMON or c in "<>":
                break
            if stop_arith and c in "+-*/%":
                break
        i -= 1
    return s[i + 1:end + 1].strip()


def _operand_right(s, start, stop_arith):
    i = start
    n = len(s)
    while i < n and s[i] in " \t\n":
        i += 1
    depth, begin = 0, i
    while i < n:
        c = s[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0:
            if c in _BOUND_COMMON or c in "<>":
                break
            if stop_arith and c in "+-*/%":
                break
        i += 1
    return s[begin:i].strip()


def _fn_units(text):
    """Yield (fn_name, start_char_offset, body_text) for each Solidity function /
    constructor / receive / fallback, brace-matched."""
    n = len(text)
    for m in _FN.finditer(text):
        name = m.group(1) or m.group(2) or m.group(3) or m.group(4) or "?"
        # find the opening brace of the body (skip the signature; a `;` first means
        # an abstract / interface declaration with no body)
        j = m.end()
        depth_paren = 0
        while j < n:
            c = text[j]
            if c == "(":
                depth_paren += 1
            elif c == ")":
                depth_paren -= 1
            elif c == ";" and depth_paren <= 0:
                j = -1
                break
            elif c == "{" and depth_paren <= 0:
                break
            j += 1
        if j == -1 or j >= n:
            continue
        # brace-match the body
        depth, k = 0, j
        while k < n:
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        yield name, j, text[j:k + 1]


def _sites(body_text):
    """Yield (op, kind, left, right, off) for every comparison / arithmetic binary
    site whose two operands are both non-trivial."""
    for m in _COMP.finditer(body_text):
        op = m.group("op")
        left = _operand_left(body_text, m.start(), stop_arith=False)
        right = _operand_right(body_text, m.end(), stop_arith=False)
        if _nontrivial(left) and _nontrivial(right):
            yield op, "comparison", left, right, m.start()
    for m in _ARITH.finditer(body_text):
        op = m.group("op")
        left = _operand_left(body_text, m.start(), stop_arith=True)
        right = _operand_right(body_text, m.end(), stop_arith=True)
        if _nontrivial(left) and _nontrivial(right):
            yield op, "arithmetic", left, right, m.start()


def _divergences(lb, rb):
    """The axes on which BOTH operands carry a confident OPPOSITE basis label."""
    out = []
    for axis, _, _ in _AXES:
        a, b = lb.get(axis), rb.get(axis)
        if a is not None and b is not None and a != b:
            out.append((axis, a, b))
    return out


# A comparison whose revert reason / custom-error selector / nearby name signals a
# PRICE or RATE bound or a share-price sanity check is a DELIBERATE cross-basis check,
# not an accidental units mismatch: `require(mintedShares >= assets, SharePriceAboveOne())`
# asserts share-price>=1 (a shares-vs-assets ORDERING is exactly the intended bound);
# `exchangeRate within band`, `peg bound`, etc. are the same pattern. Those two operands
# are SUPPOSED to be different bases - the ordering IS the economic fact - so the screen
# stays SILENT. Matching the selector/string keeps this narrow (biases toward silence).
_PRICE_RATE_BOUND = re.compile(
    r"SharePrice|Price|Rate|ExchangeRate|Peg|Bound", re.IGNORECASE)


def _enclosing_stmt(s, off):
    """The text of the single statement enclosing a binary-op at offset `off`:
    backward to the nearest `;`/`{`/`}` and forward to the nearest `;`. Used to read
    the require's revert reason / error selector that sits in the SAME statement as
    the comparison (`require(a >= b, SharePriceAboveOne())`)."""
    n = len(s)
    a = off
    while a > 0 and s[a - 1] not in ";{}":
        a -= 1
    b = off
    while b < n and s[b] != ";":
        b += 1
    return s[a:b]


def _strip_comments_keep_strings(text: str) -> str:
    """Blank out `//` and `/* */` comments but KEEP string literals, preserving
    per-char offsets. This is the view used to read a require's revert reason: a
    STRING reason (`require(x, "share price too high")`) survives, while a comment
    that merely mentions 'price'/'rate' does NOT (a comment is not an assertion of
    intent and must not suppress a genuine mismatch)."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = False
    in_str = None
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
        elif in_str is not None:
            if c == "\\":
                out.append(text[i:i + 2])
                i += 2
                continue
            if c == in_str:
                in_str = None
            out.append(c)
            i += 1
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
        elif c == '"' or c == "'":
            in_str = c
            out.append(c)
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _price_rate_bound_ctx(masked, nocomment, abs_off):
    """True when the enclosing statement's revert reason / custom-error selector /
    nearby name signals a PRICE/RATE/PEG bound or a share-price sanity check - a
    DELIBERATE cross-basis check, not an accidental units mismatch. Reads the masked
    statement (a custom-error selector / identifier survives masking, e.g.
    `SharePriceAboveOne()`) AND the comments-stripped-strings-kept statement (a STRING
    revert reason survives there, e.g. `"share price above one"`; a comment mentioning
    'price' does NOT). Offsets are source-aligned (all views preserve length)."""
    if _PRICE_RATE_BOUND.search(_enclosing_stmt(masked, abs_off)):
        return True
    if nocomment is not None and _PRICE_RATE_BOUND.search(
            _enclosing_stmt(nocomment, abs_off)):
        return True
    return False


def _stable_id(rel, fn, line, left, right, op):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{line}|{op}|{left}|{right}".encode())
    return h.hexdigest()[:16]


def scan_file(path: Path, rel: str, file_text: str = None):
    """Return candidate basis-comparison rows for one .sol file, each with a `fires`
    bool. A row FIRES iff, on some accounting axis, the two operands of a comparison /
    sum / subtraction carry a confident OPPOSITE basis (a basis divergence)."""
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask(raw)
    # a view that keeps STRING revert reasons but drops comments (offset-aligned with
    # `text`), used only to read the require's revert reason for the price/rate-bound
    # suppression - a comment mentioning 'price' must not suppress a genuine mismatch.
    nocomment = _strip_comments_keep_strings(raw)
    rows = []
    for fn, fn_off, body in _fn_units(text):
        for op, kind, left, right, off in _sites(body):
            lb = _basis(left, body)
            rb = _basis(right, body)
            divs = _divergences(lb, rb)
            abs_off = fn_off + off
            # SILENT on a deliberate cross-basis PRICE/RATE bound or share-price
            # sanity check (revert reason / error selector / nearby name) - the
            # different-basis ordering IS the intended economic invariant there,
            # not an accidental units mismatch.
            suppressed = bool(divs) and _price_rate_bound_ctx(text, nocomment, abs_off)
            fires = bool(divs) and not suppressed
            line_no = text[:abs_off].count("\n") + 1
            axis = divs[0][0] if divs else None
            rows.append({
                "schema": HYP_SCHEMA,
                "capability": CAPABILITY,
                "id": _stable_id(rel, fn, line_no, left, right, op),
                "file": rel,
                "function": fn,
                "line": line_no,
                "lang": "solidity",
                "op": op,
                "kind": kind,
                "left": left[:120],
                "right": right[:120],
                "left_basis": lb,
                "right_basis": rb,
                "divergences": [{"axis": a, "left": l, "right": r}
                                for (a, l, r) in divs],
                "axis": axis,
                "fires": fires,
                "suppressed_price_rate_bound": suppressed,
                # advisory-first contract (never auto-credit, never fail-close)
                "verdict": "needs-fuzz",
                "advisory": True,
                "auto_credit": False,
                "question": (
                    f"`{fn}` relates `{left[:56]}` {op} `{right[:56]}` "
                    + (f"but the operands diverge on the {axis} axis "
                       f"({divs[0][1]} vs {divs[0][2]}). " if divs else "")
                    + "Are both operands proven to be in the SAME accounting basis "
                    "(shares/assets, ray-scaled/raw, gross/net, rebasing/static), or "
                    "does the relation conserve nothing because they are not "
                    "commensurable?"),
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
    """Emit ONLY the firing hypotheses (basis-divergence rows) to the sidecar."""
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    fired = [r for r in rows if r.get("fires")]
    with out.open("w") as fh:
        for r in fired:
            fh.write(json.dumps(r) + "\n")
    return out, fired


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    by_axis = {}
    for r in fired:
        by_axis[r["axis"]] = by_axis.get(r["axis"], 0) + 1
    return {
        "schema": HYP_SCHEMA,
        "capability": CAPABILITY,
        "candidates": len(rows),
        "fired": len(fired),
        "by_axis": by_axis,
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def _resolve_ws(arg):
    ws = Path(arg)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / arg
        if cand.exists():
            ws = cand
    return ws


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="MQ-C02 operand-commensurability (accounting-basis) screen (advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(_STRICT_ENV, "").strip() not in ("", "0", "false")

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

    ws = _resolve_ws(args.workspace)
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
        summ = {
            "schema": HYP_SCHEMA, "capability": CAPABILITY,
            "fired": len(rows), "source": "sidecar",
            "verdict": "needs-fuzz" if rows else "clean-advisory",
            "advisory": True, "auto_credit": False,
        }
        print(json.dumps(summ, indent=2))
        return 1 if (strict and rows) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    # ADVISORY-FIRST: default exit 0; strict elevates only when a divergence exists
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
