#!/usr/bin/env python3
"""division-rounds-against-beneficiary-screen.py - GEN-4B, the VALUE-CONSERVING
DIVISION ROUNDS-AGAINST-BENEFICIARY screen (layer = pattern-lift).

CROSS-LANG: Solidity (.sol), Rust (.rs), Go (.go), Move (.move). A GENERAL
advisory screen (never a specific bug-shape). This is the CROSS-LANGUAGE LIFT of
the single-lang EVM-W3 `divide-before-multiply` detector, PLUS a net-new
`wrong-rounding-direction` arm.

GENERAL LOGIC. When a CONSERVED quantity is split by a division (assets<->shares,
fee<->principal, reward<->stake, collateral<->debt), the truncation residual must
round TOWARD the protocol / counterparty, NOT toward the quotient recipient -
else the recipient is systematically over-credited (theft-by-rounding /
dust-drain). Two mutation-verifiable arms:

  ARM 1 - DIVIDE-BEFORE-MULTIPLY (primary, mutation-verifiable core):
    `a / b * c` (or the language equivalent) where re-associating to
    `a * c / b` would preserve precision - the early divide TRUNCATES then the
    multiply AMPLIFIES the lost residual. Infix (`a / b * c`, all four langs) OR
    method-chain (`x.Quo(..).Mul(..)` Go Dec/Int, `x.checked_div(..).checked_mul
    (..)` / `.div(..).mul(..)` Rust, SafeMath `.div(..).mul(..)` Solidity).

  ARM 2 - WRONG-ROUNDING-DIRECTION (secondary, medium, harder to confirm
    statically): a payout/mint/claim amount computed with round-UP (Ceil / Up /
    ceilDiv / mulDivUp) - a user-withdrawable amount rounded up OVER-PAYS; OR a
    debt/burn/owed amount rounded DOWN (Floor / Down / mulDivDown) - a debt
    rounded down UNDER-CHARGES. The correct pairing (payout DOWN, debt UP) stays
    SILENT.

CROSS-LANG MAP (this LIFTS the EVM-W3 detector to all fleet langs):
  * Solidity: `a / b * c`; `Math.mulDiv(x,y,z, Rounding.Ceil)` / `mulDivUp` on a
    payout; SafeMath `.div(..).mul(..)`.
  * Rust: fixed-point `a / b * c` on u128/U256; `.checked_div(..).checked_mul(..)`
    reorder; `Decimal`/`Ratio` `.div(..).mul(..)`; `Ceil`/`round_up` on a payout.
  * Go cosmos: `sdk.Dec.Quo(..).Mul(..)` (Quo before Mul); `sdk.Int` integer `/`
    then `*`; `.QuoInt(..).MulInt(..)`; `.Ceil()` on a payout Dec.
  * Move: `a / b * c` on u64/u128.

FP-CONTROL (critical - not every division):
  * The operands must plausibly be a CONSERVED / value-bearing quantity
    (amount/shares/assets/balance/reward/fee/stake/collateral/debt/principal/
    price identifiers, or feeding a transfer/mint/withdraw). NO conserved hint
    anywhere (operands, statement, enclosing fn name) -> SILENT.
  * The DBM pattern must be a GENUINE divide-before-multiply (a `/` whose result
    is then `*`-ed). A multiply-before-divide `a * b / c` (the CORRECT order) is
    NEVER matched by the infix detector and stays SILENT.
  * A pure `x / N` with no following multiply, an index/loop divisor, or a bare
    ratio for display -> SILENT.
  * DBM severity: HIGH only when a conserved hint is present in the ARITHMETIC
    OPERANDS (strong); when the hint is only in the statement / fn name
    (conservedness UNCERTAIN) -> MEDIUM. The WRD arm is always MEDIUM.

DEDUP (tool-duplication preflight, do-NOT #10 - cite):
  * EVM-W3 `divide-before-multiply` (glider gap set, task_W3) is SINGLE-LANG
    (Solidity only). GEN-4B LIFTS the concept to Rust/Go/Move AND adds the
    wrong-rounding-direction arm. `cross_lang_detector_map` has NO
    division-rounding row - GEN-4B is that net-new cross-lang JOIN.
  * Distinct from GEN-R5 `release-silent-overflow-screen` (untrusted-arith WRAPS
    into a MEMORY-safety sink) - that is memory-safety, not value-conservation.
    GEN-4B keys on a CONSERVED-quantity split rounding against the beneficiary.
  A site that reduces to W3-on-Solidity-only keeps the cross-lang arms + the
  wrong-rounding-direction arm as the net-new.

nuva has BOTH Go (cosmos) and EVM (Solidity) surface -> nuva-verify is IN SCOPE.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False; exit 0 by default. The opt-in env
AUDITOOOR_DIVISION_ROUNDS_STRICT (or --strict) raises the exit code when a fired
row exists. Excludes test / vendor / codegen via the shared exclusion libs.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/
                     division_rounds_against_beneficiary_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single .sol/.rs/.go/.move file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a fired row exists
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

HYP_SCHEMA = "auditooor.division_rounds_against_beneficiary_hypotheses.v1"
_SIDE_NAME = "division_rounds_against_beneficiary_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_DIVISION_ROUNDS_STRICT"
_CAPABILITY = "GEN_4B"

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


_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "examples", "example", "script",
              "scripts", "deployments", "prior_audits", "reference", "certora",
              "simulation", "testdata", "mocks", "mock", "artifacts", "fuzz",
              "lib", "libs", "third_party", "node-modules",
              "chimera_harnesses"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|testutil|testonly|testhelper|test_fixtures|mock|mocks|"
    r"benches|benchmarks?|examples?|fixtures|simulation|testdata|poc|pocs|"
    r"chimera_harnesses)(/|$)")
_CODEGEN_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)
_CODEGEN_SUFFIX = (".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go",
                   "_generated.go", ".pb.validate.go")
_EXT_TO_LANG = {".sol": "solidity", ".rs": "rust", ".go": "go",
                ".move": "move"}


# ============================================================================
# Comment / string masking (length-preserving). Handles // and /* */ and
# "..." / '...' / `...` strings. Move/Sol/Go/Rust all fit this shape; Rust '
# lifetimes are handled by only treating ' as a string when it closes shortly.
# ============================================================================
def _mask(text: str) -> str:
    out = []
    i, n = 0, len(text)
    in_line = in_block = False
    in_str = False
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
            out.append("\n" if c == "\n" else " ")
            if c == "\\":
                out.append(" ")
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
        elif c == '"' or c == "`":
            in_str = True
            quote = c
            out.append(" ")
            i += 1
        elif c == "'":
            # Rust lifetime (`'a`) vs char literal (`'x'`). Treat as a string
            # only if a matching close-quote appears within 4 chars.
            close = text.find("'", i + 1, i + 5)
            if close != -1 and (close - i) <= 4:
                in_str = True
                quote = "'"
                out.append(" ")
                i += 1
            else:
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
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _excerpt(raw: str, off: int) -> str:
    ls = raw.rfind("\n", 0, off) + 1
    le = raw.find("\n", off)
    if le == -1:
        le = len(raw)
    return raw[ls:le].strip()[:200]


def _line_span(masked: str, off: int):
    ls = masked.rfind("\n", 0, off) + 1
    le = masked.find("\n", off)
    if le == -1:
        le = len(masked)
    return ls, le


def _stable_id(rel, arm, subject, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{arm}|{subject}|{line}".encode())
    return h.hexdigest()[:16]


# ============================================================================
# balanced extraction
# ============================================================================
def _balanced(text: str, open_idx: int, opener="(", closer=")"):
    depth = 0
    n = len(text)
    i = open_idx
    while i < n:
        ch = text[i]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


# ============================================================================
# cross-lang function span index -> attribute a hit offset to its enclosing fn
# ============================================================================
_FN_DECL_RE = re.compile(
    r"(?:"
    r"function\s+(?P<sol>[A-Za-z_]\w*)"                     # Solidity
    r"|func\s+(?:\([^)]*\)\s*)?(?P<go>[A-Za-z_]\w*)"        # Go
    r"|(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?fn\s+(?P<rs>[A-Za-z_]\w*)"  # Rust
    r"|(?:public\s+|entry\s+|native\s+)*fun\s+(?P<mv>[A-Za-z_]\w*)"  # Move
    r")")


def _fn_spans(masked: str):
    """Return sorted list of (body_start, body_end, name)."""
    spans = []
    for m in _FN_DECL_RE.finditer(masked):
        name = (m.group("sol") or m.group("go") or m.group("rs")
                or m.group("mv") or "<anon>")
        bopen = masked.find("{", m.end())
        if bopen == -1:
            continue
        # a ';' before '{' -> interface / abstract decl, no body.
        semi = masked.find(";", m.end())
        if semi != -1 and semi < bopen:
            continue
        bclose = _balanced(masked, bopen, "{", "}")
        if bclose == -1:
            continue
        spans.append((bopen, bclose, name))
    spans.sort()
    return spans


def _fn_of(spans, off):
    """Innermost enclosing fn name for an offset (spans sorted by start)."""
    best = "<file-scope>"
    best_start = -1
    for bstart, bend, name in spans:
        if bstart <= off <= bend and bstart > best_start:
            best = name
            best_start = bstart
    return best


# ============================================================================
# conserved-quantity hint
# ============================================================================
_CONSERVED_RE = re.compile(
    r"(amount|amt|shares?|assets?|balance|reward|fee|stake|staked|collateral|"
    r"debt|principal|payout|withdraw|redeem|claim|deposit|supply|borrow|owed|"
    r"minted|mint|liquidity|dividend|interest|yield|refund|allocation|proceeds|"
    r"equity|premium|underlying|wad|weight|coins?|repay|owe|earn|accrued|"
    r"pooled|token(?:s|amount)?|nav|aum|coll)",
    re.I)
# a value-moving sink adjacent to the arithmetic strengthens the conserved read.
_VALUE_SINK_RE = re.compile(
    r"(transfer|safeTransfer|_mint|\bmint\b|_burn|\bburn\b|withdraw|payout|"
    r"SendCoins|AddCoins|SubtractCoins|BankKeeper|coin(?:s)?\b)", re.I)


def _conserved_strength(operand_snippet: str, statement: str, fn_name: str):
    """('strong'|'weak'|None, hint_tokens)."""
    m = _CONSERVED_RE.search(operand_snippet)
    if m:
        return "strong", m.group(0)
    m = (_CONSERVED_RE.search(statement) or _CONSERVED_RE.search(fn_name)
         or _VALUE_SINK_RE.search(statement))
    if m:
        return "weak", m.group(0)
    return None, ""


# ============================================================================
# ARM 1: divide-before-multiply (infix)   a / <atom> * c
# ============================================================================
_IDENT_CH = re.compile(r"[A-Za-z0-9_]")
# Solidity number units (`1 ether`, `2 days`): a unit keyword after a literal is
# part of the same operand, not the next term.
_SOL_UNITS = {"ether", "wei", "gwei", "finney", "szabo", "seconds", "minutes",
              "hours", "days", "weeks", "years"}
_WORD_RE = re.compile(r"[A-Za-z_]\w*")


def _skip_atom(text: str, j: int):
    """Consume the right operand of a `/` starting at index j. Return end index
    (exclusive) or -1 if not a parseable atom."""
    n = len(text)
    while j < n and text[j] in " \t":
        j += 1
    # leading unary
    while j < n and text[j] in "-+!~":
        j += 1
        while j < n and text[j] in " \t":
            j += 1
    if j >= n:
        return -1
    if text[j] == "(":
        close = _balanced(text, j, "(", ")")
        if close == -1:
            return -1
        j = close + 1
    elif _IDENT_CH.match(text[j]):
        while j < n and (_IDENT_CH.match(text[j]) or text[j] == "."):
            j += 1
        # Solidity number-unit: `1 ether`, `2 days` -> the unit is part of the
        # same operand (only after a bare numeric literal).
        k = j
        while k < n and text[k] in " \t":
            k += 1
        wm = _WORD_RE.match(text, k)
        if wm and wm.group(0) in _SOL_UNITS:
            j = wm.end()
    else:
        return -1
    # trailing call / index / method chains
    while j < n:
        while j < n and text[j] in " \t":
            j += 1
        if j < n and text[j] == "(":
            close = _balanced(text, j, "(", ")")
            if close == -1:
                return -1
            j = close + 1
        elif j < n and text[j] == "[":
            close = _balanced(text, j, "[", "]")
            if close == -1:
                return -1
            j = close + 1
        elif j < n and text[j] == "." and (j + 1 < n and _IDENT_CH.match(text[j + 1])):
            j += 1
            while j < n and (_IDENT_CH.match(text[j]) or text[j] == "."):
                j += 1
        else:
            break
    return j


def _find_dbm_infix(masked: str):
    """Yield (div_offset, snippet) for `a / <atom> * c` divide-before-multiply."""
    n = len(masked)
    for i, c in enumerate(masked):
        if c != "/":
            continue
        nxt = masked[i + 1] if i + 1 < n else ""
        prv = masked[i - 1] if i > 0 else ""
        if nxt in ("/", "*", "="):        # //, /*, /=  (masked leaves none, be safe)
            continue
        if prv == "/":                    # part of // (defensive)
            continue
        # binary division: the char before (non-space) must end an operand.
        k = i - 1
        while k >= 0 and masked[k] in " \t":
            k -= 1
        if k < 0 or not (masked[k] in ")]" or _IDENT_CH.match(masked[k])):
            continue
        end = _skip_atom(masked, i + 1)
        if end == -1:
            continue
        j = end
        while j < n and masked[j] in " \t":
            j += 1
        if j < n and masked[j] == "*":
            aft = masked[j + 1] if j + 1 < n else ""
            if aft in ("*", "="):          # ** pow, *= assign
                continue
            ls, le = _line_span(masked, i)
            yield i, masked[ls:le].strip()[:200]


# ============================================================================
# ARM 1: divide-before-multiply (method chain)  x.div(..).mul(..)
# ============================================================================
_DIV_METHOD_RE = re.compile(
    r"\.\s*(QuoInt64|QuoInt|QuoRaw|QuoTruncate|Quo|checked_div|wrapping_div|"
    r"saturating_div|div_euclid|div|divide)\s*\(")
_MUL_METHOD_RE = re.compile(
    r"^\.\s*(MulInt64|MulInt|MulRaw|MulTruncate|Mul|checked_mul|wrapping_mul|"
    r"saturating_mul|mul|multiply)\s*\(")
# value-preserving pass-throughs Rust chains commonly put between div and mul.
_PASSTHRU_RE = re.compile(
    r"^\s*(?:\?|\.\s*(?:unwrap|expect|unwrap_or|unwrap_or_default|unwrap_or_else"
    r"|ok_or|ok_or_else|into|to_owned|clone)\s*)")


def _find_dbm_chain(masked: str):
    """Yield (offset, snippet, div_method) for `.<div>(..).<mul>(..)`, tolerating
    intervening value-preserving pass-throughs (`.unwrap()`, `?`, `.expect(..)`)."""
    n = len(masked)
    for m in _DIV_METHOD_RE.finditer(masked):
        popen = masked.find("(", m.end() - 1)
        if popen == -1:
            continue
        close = _balanced(masked, popen, "(", ")")
        if close == -1:
            continue
        j = close + 1
        # skip value-preserving pass-throughs (unwrap/expect/?/into/clone)
        for _ in range(6):
            while j < n and masked[j] in " \t\r\n":
                j += 1
            pm = _PASSTHRU_RE.match(masked[j:j + 24])
            if not pm:
                break
            j += pm.end()
            # consume a trailing (...) if the pass-through was a call
            while j < n and masked[j] in " \t\r\n":
                j += 1
            if j < n and masked[j] == "(":
                pc = _balanced(masked, j, "(", ")")
                if pc == -1:
                    break
                j = pc + 1
        while j < n and masked[j] in " \t\r\n":
            j += 1
        tail = masked[j:j + 24]
        mm = _MUL_METHOD_RE.match(tail)
        if not mm:
            continue
        ls, le = _line_span(masked, m.start())
        yield m.start(), masked[ls:le].strip()[:200], m.group(1)


# ============================================================================
# ARM 2: wrong-rounding-direction
#   fire = round-UP on a payout hint, OR round-DOWN on a debt hint.
# ============================================================================
_ROUND_UP_RE = re.compile(
    r"\b(mulDivUp|mulDivRoundingUp|divUp|ceilDiv|wadDivUp|toUintUp)\b"
    r"|Rounding\s*\.\s*(?:Ceil|Up)"
    r"|\.\s*(?:ceil|round_up|div_ceil|checked_ceil)\s*\(")
_ROUND_DOWN_RE = re.compile(
    r"\b(mulDivDown|divDown|floorDiv|wadDivDown|toUintDown)\b"
    r"|Rounding\s*\.\s*(?:Floor|Down)"
    r"|\.\s*(?:floor|round_down|div_floor)\s*\(")
_PAYOUT_HINT_RE = re.compile(
    r"(payout|withdraw|redeem|claim|reward|proceeds|refund|dividend|yield|"
    r"assetsOut|sharesOut|amountOut|_mint\b|\bmint\b|earn|owed?ToUser|"
    r"receiv|creditedTo)", re.I)
_DEBT_HINT_RE = re.compile(
    r"(debt|owed|borrow|repay|liabilit|burn|owe|assetsIn|sharesIn|amountIn|"
    r"chargedTo|due\b)", re.I)


def _find_wrong_rounding(masked: str):
    """Yield (offset, snippet, direction) where a payout rounds UP or a debt
    rounds DOWN (the recipient-favouring / protocol-losing direction)."""
    seen = set()
    for m in _ROUND_UP_RE.finditer(masked):
        ls, le = _line_span(masked, m.start())
        line = masked[ls:le]
        if _PAYOUT_HINT_RE.search(line) and not _DEBT_HINT_RE.search(line):
            key = (m.start(),)
            if key in seen:
                continue
            seen.add(key)
            yield m.start(), line.strip()[:200], "round-up-payout"
    for m in _ROUND_DOWN_RE.finditer(masked):
        ls, le = _line_span(masked, m.start())
        line = masked[ls:le]
        if _DEBT_HINT_RE.search(line) and not _PAYOUT_HINT_RE.search(line):
            key = (m.start(),)
            if key in seen:
                continue
            seen.add(key)
            yield m.start(), line.strip()[:200], "round-down-debt"


# ============================================================================
# row construction
# ============================================================================
def _mk_row(rel, fn, line, lang, arm, conserved_hint, excerpt, severity, why):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, arm, fn + "|" + conserved_hint, line),
        "file": rel,
        "line": line,
        "function": fn,
        "lang": lang,
        "arm": arm,
        "conserved_hint": conserved_hint,
        "excerpt": excerpt,
        "severity": severity,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


# ============================================================================
# scan a single file
# ============================================================================
def scan_file(path: Path, rel: str, file_text: str = None):
    ext = "." + rel.lower().rsplit(".", 1)[-1] if "." in rel else ""
    lang = _EXT_TO_LANG.get(ext)
    if lang is None:
        return []
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    masked = _mask(raw)
    spans = _fn_spans(masked)
    rows = []
    seen = set()

    def _arith_window(off):
        """The RHS/sub-expression around the operator (between statement
        delimiters) - the actual OPERANDS, excluding a fn name on the line."""
        lo = off
        while lo > 0 and masked[lo - 1] not in ";{}(":
            lo -= 1
        hi = off
        n = len(masked)
        while hi < n and masked[hi] not in ";}{,":
            hi += 1
        return masked[lo:hi]

    def _emit(off, snippet, arm, direction=None):
        line = _line_of_offset(masked, off)
        fn = _fn_of(spans, off)
        ls, le = _line_span(masked, off)
        statement = masked[ls:le]
        operands = _arith_window(off)
        if arm == "divide-before-multiply":
            strength, hint = _conserved_strength(operands, statement, fn)
            if strength is None:
                return  # FP-control: not a conserved quantity -> SILENT
            severity = "high" if strength == "strong" else "medium"
            why = (
                "divide-before-multiply on a conserved quantity (hint=`%s`, "
                "%s): the early `/` TRUNCATES the residual, then the `*` "
                "AMPLIFIES the lost precision so the quotient recipient is "
                "under/over-credited. Re-associating to multiply-before-divide "
                "(`a * c / b`) preserves precision. %s"
            ) % (hint, "in-operand=strong" if strength == "strong"
                 else "operand-uncertain=weak (conservedness inferred from "
                      "statement/fn-name -> medium)",
                 "Cross-lang lift of EVM-W3; mutation = re-order to the "
                 "correct multiply-before-divide and re-run.")
        else:  # wrong-rounding-direction
            strength, hint = _conserved_strength(operands, statement, fn)
            if strength is None:
                return
            severity = "medium"  # secondary arm, harder to confirm statically
            why = (
                "wrong-rounding-direction on a conserved split (%s, hint=`%s`): "
                "a %s. The value-preserving direction is payout-DOWN / debt-UP; "
                "this rounds the OTHER way, systematically favouring the "
                "recipient over the protocol (theft-by-rounding / dust-drain). "
                "Tagged medium - the beneficiary/direction pairing needs a "
                "runtime confirm."
            ) % (direction, hint,
                 "user-withdrawable payout rounded UP (over-pays)"
                 if direction == "round-up-payout"
                 else "debt/owed amount rounded DOWN (under-charges)")
        excerpt = _excerpt(raw, off)
        key = (line, arm, snippet[:48])
        if key in seen:
            return
        seen.add(key)
        rows.append(_mk_row(rel, fn, line, lang, arm, hint, excerpt,
                            severity, why))

    for off, snippet in _find_dbm_infix(masked):
        _emit(off, snippet, "divide-before-multiply")
    for off, snippet, _dm in _find_dbm_chain(masked):
        _emit(off, snippet, "divide-before-multiply")
    for off, snippet, direction in _find_wrong_rounding(masked):
        _emit(off, snippet, "wrong-rounding-direction", direction)

    return rows


# ============================================================================
# tree walk + sidecar
# ============================================================================
def _iter_source_files(root: Path, workspace: Path = None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        norm = dp.replace(os.sep, "/")
        if _TEST_HINT.search(norm):
            continue
        for f in fn:
            low = f.lower()
            ext = "." + low.rsplit(".", 1)[-1] if "." in low else ""
            if ext not in _EXT_TO_LANG:
                continue
            if low.endswith(_CODEGEN_SUFFIX):
                continue
            if low.startswith("test") or low.startswith("mock") \
                    or "_test." in low or ".t.sol" in low or low == "tests.rs":
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            rel = str(p)
            if (is_test_target_path(rel)
                    or is_chimera_mutation_harness_path(rel)
                    or is_codegen_path(rel, workspace)):
                continue
            try:
                head = p.read_text(encoding="utf-8", errors="replace")[:4096]
                if _CODEGEN_SENTINEL.search(head):
                    continue
            except OSError:
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


def _count(rows, key):
    out = {}
    for r in rows:
        v = str(r.get(key, ""))
        out[v] = out.get(v, 0) + 1
    return out


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "sites": len(rows),
        "fired": len(fired),
        "by_lang": _count(rows, "lang"),
        "by_arm": _count(rows, "arm"),
        "by_severity": _count(rows, "severity"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-4B value-conserving division rounds-against-beneficiary "
                    "screen (cross-lang, advisory)")
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
        for base in ("/Users/wolf/audits", os.getcwd()):
            cand = Path(base) / args.workspace
            if cand.exists():
                ws = cand
                break
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(line) for line in side.read_text().splitlines()
                    if line.strip()]
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
