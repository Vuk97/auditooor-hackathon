#!/usr/bin/env python3
"""discarded-fallible-result-screen.py - GEN-4D, the DISCARDED-FALLIBLE-RESULT
-ON-A-VALUE-PATH screen (layer = pattern-lift, cross-language advisory).

GENERAL. A FALLIBLE operation on a VALUE-MOVING path (transfer / mint / burn /
send / withdraw / deposit / settle / coin / balance) whose error / failure
signal is DISCARDED lets a FAILED transfer proceed as if it SUCCEEDED. The
downstream code then credits / debits / settles on the false premise that the
value move happened - phantom credit, lost funds, or a double-spend. This is the
classic `errcheck` bug lifted to a value-path taint and generalized across Go,
Rust and Move.

FIRES (per language) when BOTH hold:
  (a) the call is on a VALUE path - the callee identifier carries a value-move
      hint (`transfer` / `send` / `sendcoins` / `mint` / `burn` / `withdraw` /
      `deposit` / `settle` / `escrow` / `refund` / `payout` / `redeem` /
      `checked_sub`/`checked_add` on a `balance`/`amount` receiver ...); AND
  (b) the FALLIBLE result is DISCARDED - the error / `Result` / `bool`-success
      is thrown away with NO check:
        Go   : `_ = k.SendCoins(...)`, `_, _ = ...`, `x, _ = ...` (blank in the
               error position), OR a BARE expression-statement call to a
               known-error-returning cosmos bank value op (`SendCoins` /
               `MintCoins` / `BurnCoins` / ... never assigned, never `if err :=`).
        Rust : `let _ = x.transfer(...)`, `x.transfer(...).ok();` (discard via
               `.ok()` as a statement), `let _ = amount.checked_sub(...)`.
        Move : `let _ = coin::...`, `_ = <coinop>(...)` discarding an
               abort-code / bool from a coin op.

FP-CONTROL (critical - a discard is only a bug on a VALUE, FALLIBLE path):
  * the discarded result MUST be on a value path (value-move identifier hint) -
    a discarded getter / logger / pure call is SILENT.
  * an EXPLICITLY-HANDLED error is SILENT: Go `if err := f(); err != nil`,
    `err != nil`, a named non-blank result that is later inspected; Rust `?`,
    `.unwrap()` / `.expect()`, `match`, `if let Ok/Err`; a `require`/assert.
  * a `_ = f()` where `f` is infallible / not a value op is SILENT.
  * the Go bare-statement arm is restricted to a CURATED set of always-
    error-returning cosmos bank ops (no generic `.Send()` / `.Transfer()` bare
    statement, which is FP-prone) - the blank-assign arm carries the broad hint
    set because `_ =` is an unambiguous discard.

DEDUP (tool-duplication preflight, do-NOT #10 - cite):
  * Solidity low-level-call return-value discard is ALREADY covered by W6-P1
    (unchecked-return-value detector, tools/glider queries / detector-runner).
    GEN-4D does NOT scan `.sol`; it covers the Go / Rust / Move discarded
    err/Result/bool on a value path that W6-P1 does not reach. A Solidity site
    defers to W6-P1 (cited here).
  * distinct from `release-silent-overflow-screen.py` (GEN-R5), which flags a
    release-mode WRAPPED arithmetic value reaching a MEMORY sink - a wrong value,
    not a discarded failure signal.

NUVA-VERIFY: this is a Go value-op capability; nuva has a Go cosmos surface, so
nuva-verify is IN SCOPE and its verdict is recorded in the dispatch report.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False; exit 0 by default. The opt-in env
AUDITOOOR_DISCARDED_FALLIBLE_RESULT_STRICT (or --strict) raises the exit code
when a fired row exists.

Excludes test / vendor / codegen via the shared exclusion libs.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/
                     discarded_fallible_result_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single .go/.rs/.move file, print rows as JSON
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

HYP_SCHEMA = "auditooor.discarded_fallible_result_hypotheses.v1"
_SIDE_NAME = "discarded_fallible_result_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_DISCARDED_FALLIBLE_RESULT_STRICT"
_CAPABILITY = "GEN_4D"

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
              "chimera_harnesses", "third_party", "proto"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|testutil|testonly|testhelper|test_fixtures|mock|mocks|"
    r"benches|benchmarks?|examples?|fixtures|simulation|testdata|poc|pocs|"
    r"chimera_harnesses|apptesting)(/|$)")
_CODEGEN_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)

_EXTS = (".go", ".rs", ".move")


# ============================================================================
# comment / string masking (Go + Rust + Move all use // /* */ and "...").
# A backtick raw string (Go) is also masked. Single-quote is a rune/char/
# lifetime marker - left intact (lifetimes survive; runes are rare on our
# value-op lines).
# ============================================================================
def _mask(text: str) -> str:
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = in_raw = False
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
        elif in_raw:  # Go backtick raw string
            out.append("\n" if c == "\n" else " ")
            if c == "`":
                in_raw = False
            i += 1
        elif in_str:
            out.append(" ")
            if c == "\\":
                out.append(" ")
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(" ")
            i += 1
        elif c == "`":
            in_raw = True
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


def _line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _excerpt(text: str, off: int) -> str:
    ls = text.rfind("\n", 0, off) + 1
    le = text.find("\n", off)
    if le == -1:
        le = len(text)
    return text[ls:le].strip()[:200]


def _stable_id(rel, arm, subject, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{arm}|{subject}|{line}".encode())
    return h.hexdigest()[:16]


def _balanced_parens(text: str, open_idx: int):
    """(inner, close_idx) for a '(' at text[open_idx]. -1 if unbalanced."""
    depth = 0
    n = len(text)
    i = open_idx
    while i < n:
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i
        i += 1
    return "", -1


# ============================================================================
# value-path lexicon (the (a) predicate). A call is on a VALUE path iff the
# callee identifier - split into camelCase / snake_case WORDS - carries a value
# verb. STRONG verbs are unambiguous value-moves and fire alone; WEAK verbs
# (`send`, `pay`, ... - which also name channel/message/mutex ops) fire ONLY
# when a VALUE NOUN co-occurs in the callee words OR the call arguments. Word-
# exact matching (not substring) so `Sender` / `release_lock` do NOT match.
# ============================================================================
_STRONG_VERBS = {
    "transfer", "mint", "burn", "withdraw", "escrow", "unescrow", "refund",
    "payout", "redeem", "disburse", "remit", "settle", "undelegate",
    "unstake", "unbond", "mintcoins", "burncoins", "sendcoins",
}
_WEAK_VERBS = {
    "send", "pay", "credit", "debit", "release", "spend", "collect", "sweep",
    "distribute", "reward", "slash", "stake", "delegate", "bond", "move",
    "deliver", "deposit",
}
# NB: `value` is deliberately EXCLUDED - it is an extremely common variable
# name (network `value`, protobuf `value`, map `value`) and collides with
# channel/message sends, spraying FPs. Value moves name a concrete asset noun.
_VALUE_NOUNS = {
    "coin", "coins", "token", "tokens", "fund", "funds", "amount", "amt",
    "asset", "assets", "money", "payment", "balance", "balances",
    "fee", "fees", "reward", "rewards", "denom", "wei", "ether", "share",
    "shares", "collateral", "debt", "principal", "stake",
}
# a value-move receiver/subject hint for the checked_ arithmetic case.
_BALANCE_SUBJECT_RE = re.compile(
    r"\b(balance|balances|amount|amt|coins?|funds?|shares?|assets?|"
    r"reserve|liquidity|supply|deposit|collateral|debt)\b", re.I)
# arithmetic method names whose discarded Result matters on a balance path.
_CHECKED_ARITH_RE = re.compile(
    r"\bchecked_(?:add|sub|mul|div|pow|rem)\b")


def _callee_name(before: str):
    """Return the trailing dotted-call callee token, e.g. 'k.bankKeeper.
    SendCoins' -> 'SendCoins'. `before` is the text immediately preceding '('.
    """
    m = re.search(r"([A-Za-z_]\w*)\s*$", before)
    return m.group(1) if m else ""


def _ident_words(ident: str):
    """Split a camelCase / snake_case / kebab identifier into lowercase words:
    'SendCoinsFromModule' -> {'send','coins','from','module'}."""
    parts = re.split(r"[_\-\s]+", ident)
    words = set()
    for p in parts:
        # split camelCase / PascalCase / acronym boundaries.
        for w in re.findall(
                r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z]+", p):
            words.add(w.lower())
    return words


def _value_hint(callee: str, context: str = "") -> str:
    """Return the value verb if `callee` is a value op, else ''. `context` is
    the surrounding call text (args) used to satisfy the WEAK-verb value-noun
    requirement."""
    words = _ident_words(callee)
    lc = callee.lower()
    if lc in _STRONG_VERBS:
        return lc
    strong = words & _STRONG_VERBS
    if strong:
        return sorted(strong)[0]
    weak = words & _WEAK_VERBS
    if weak:
        ctx_words = words | _ident_words(context)
        if ctx_words & _VALUE_NOUNS:
            return sorted(weak)[0]
    return ""


def _is_value_call(callee: str, context: str = "") -> bool:
    return bool(_value_hint(callee, context))


# curated always-error-returning cosmos bank ops for the Go bare-statement arm.
_GO_BARE_STMT_OPS = re.compile(
    r"\b(SendCoins|SendCoinsFromModuleToAccount|SendCoinsFromAccountToModule|"
    r"SendCoinsFromModuleToModule|MintCoins|BurnCoins|DelegateCoins|"
    r"UndelegateCoins|SendCoinsFromModuleToManyAccounts)\b")


# ============================================================================
# GO arm
# ============================================================================
# discard-assign: `_ = <call>`, `_, _ = <call>`, `x, _ = <call>` where a blank
# sits in the LHS. We require at least one `_` in the LHS tuple, then check the
# RHS is a value call. `:=` short-decl with a blank also counts.
_GO_DISCARD_ASSIGN_RE = re.compile(
    r"(?m)^[ \t]*(?P<lhs>[A-Za-z_]\w*(?:\s*,\s*(?:[A-Za-z_]\w*|_))*"
    r"|_(?:\s*,\s*(?:[A-Za-z_]\w*|_))*)\s*(?::?=)\s*(?P<rhs>[^\n]*)")


def _go_lhs_discards_error(lhs: str) -> bool:
    """Go convention: the error is the LAST return value. The error is DISCARDED
    iff the LAST LHS element is the blank `_` (covers single `_ =`, `x, _ =`,
    `_, _ =`). A `_, err =` keeps the error in `err` -> NOT a discard."""
    parts = [p.strip() for p in lhs.split(",")]
    return bool(parts) and parts[-1] == "_"


def scan_go(text: str, rel: str):
    rows, seen = [], set()

    # -- arm 1: discard-assign of a value call --------------------------------
    for m in _GO_DISCARD_ASSIGN_RE.finditer(text):
        lhs, rhs = m.group("lhs"), m.group("rhs")
        if not _go_lhs_discards_error(lhs):
            continue
        # the RHS must be (or start with) a call whose callee is a value op.
        popen = rhs.find("(")
        if popen == -1:
            continue
        callee = _callee_name(rhs[:popen])
        is_val = _is_value_call(callee, rhs)
        arith = False
        if not is_val and _CHECKED_ARITH_RE.search(rhs) \
                and _BALANCE_SUBJECT_RE.search(rhs):
            is_val, arith = True, True
        if not is_val:
            continue
        off = m.start("rhs")
        line = _line_of_offset(text, off)
        key = ("go-discard", line, callee)
        if key in seen:
            continue
        seen.add(key)
        hint = "checked-arith-on-balance" if arith else _value_hint(callee, rhs)
        rows.append(_mk_row(
            rel, _enclosing_fn(text, off), line, "go-discard-assign",
            callee or "checked_arith", "go", hint,
            _excerpt(text, off), "high" if not arith else "medium",
            ("a returned error from the value-moving call `%s(...)` is "
             "assigned to the blank identifier `_` and never inspected; a "
             "FAILED transfer/mint/burn silently proceeds as success, leaving "
             "the downstream credit/debit on a false premise (phantom "
             "credit / lost funds)." % (callee or "checked_arith"))))

    # -- arm 2: bare expression-statement of a curated cosmos bank op ---------
    for m in _GO_BARE_STMT_OPS.finditer(text):
        # find the '(' that follows this op token.
        popen = text.find("(", m.end())
        if popen == -1 or popen - m.end() > 2:
            continue
        # is this a bare statement? examine the text before the callee on the
        # same logical line.
        line_start = text.rfind("\n", 0, m.start()) + 1
        prefix = text[line_start:m.start()]
        # REQUIRE a receiver dotted-path immediately before the op
        # (e.g. `k.bankKeeper.`). This excludes interface / func-type method
        # SIGNATURES (`SendCoins(ctx ...) error`), which have no receiver and
        # are declarations, not calls.
        recv = re.search(r"([A-Za-z_]\w*)(\s*\.\s*[A-Za-z_]\w*)*\s*\.\s*$",
                         prefix)
        if not recv:
            continue
        # strip the receiver dotted path; what remains must be empty (bare
        # statement) or only a leading `defer`/`go` keyword.
        head = prefix[:recv.start()].strip()
        if head and not re.fullmatch(r"(defer|go)?", head):
            continue
        line = _line_of_offset(text, m.start())
        callee = m.group(0)
        key = ("go-bare", line, callee)
        if key in seen:
            continue
        seen.add(key)
        rows.append(_mk_row(
            rel, _enclosing_fn(text, m.start()), line, "go-bare-statement",
            callee, "go", _value_hint(callee) or callee.lower(),
            _excerpt(text, m.start()), "high",
            ("`%s(...)` always returns an error but is invoked as a bare "
             "statement - its error is DISCARDED. A failed coin move "
             "silently proceeds as success (phantom credit / lost funds)."
             % callee)))

    return rows


# ============================================================================
# RUST arm
# ============================================================================
# `let _ = <call>` / `let _ = <expr>.method(...)` discarding a Result.
_RS_LET_UNDERSCORE_RE = re.compile(r"(?m)^[ \t]*let\s+_\s*=\s*(?P<rhs>[^\n]*)")
# `<expr>.ok();` discard-as-statement (Result -> Option dropped).
_RS_DOT_OK_RE = re.compile(r"(?P<call>[^\n;]*?)\.\s*ok\s*\(\s*\)\s*;")


def scan_rust(text: str, rel: str):
    rows, seen = [], set()

    # -- arm 1: `let _ = <value call>` ---------------------------------------
    for m in _RS_LET_UNDERSCORE_RE.finditer(text):
        rhs = m.group("rhs")
        popen = rhs.find("(")
        if popen == -1:
            continue
        callee = _callee_name(rhs[:popen])
        is_val = _is_value_call(callee, rhs)
        arith = False
        if not is_val and _CHECKED_ARITH_RE.search(rhs) \
                and _BALANCE_SUBJECT_RE.search(rhs):
            is_val, arith = True, True
        if not is_val:
            continue
        off = m.start("rhs")
        line = _line_of_offset(text, off)
        key = ("rs-let", line, callee)
        if key in seen:
            continue
        seen.add(key)
        hint = "checked-arith-on-balance" if arith else _value_hint(callee, rhs)
        rows.append(_mk_row(
            rel, _enclosing_fn_rs(text, off), line, "rust-let-underscore",
            callee or "checked_arith", "rust", hint,
            _excerpt(text, off), "high" if not arith else "medium",
            ("the `Result` of the value-moving call `%s(...)` is bound to "
             "`let _` and dropped; a failed transfer/mint returns `Err` that "
             "is never propagated (no `?`/`match`/`unwrap`), so a failed value "
             "move proceeds as success (phantom credit / lost funds)."
             % (callee or "checked_arith"))))

    # -- arm 2: `<value call>.ok();` discard-as-statement --------------------
    for m in _RS_DOT_OK_RE.finditer(text):
        call = m.group("call")
        popen = call.rfind("(")
        if popen == -1:
            continue
        # callee is the token before the LAST call-paren on this expr.
        # find matching open for the closing before `.ok`.
        callee = ""
        # scan for the outermost value-op token in the call chain (context =
        # the whole call expression so WEAK verbs see their args/nouns).
        for cm in re.finditer(r"([A-Za-z_]\w*)\s*\(", call):
            if _is_value_call(cm.group(1), call):
                callee = cm.group(1)
                break
        if not callee:
            continue
        off = m.start("call")
        line = _line_of_offset(text, off)
        key = ("rs-ok", line, callee)
        if key in seen:
            continue
        seen.add(key)
        rows.append(_mk_row(
            rel, _enclosing_fn_rs(text, off), line, "rust-dot-ok-discard",
            callee, "rust", _value_hint(callee, call),
            _excerpt(text, off), "high",
            ("the `Result` of the value-moving call `%s(...)` is discarded via "
             "`.ok()` as a statement (the `Err` is silently converted to "
             "`None` and dropped); a failed value move proceeds as success "
             "(phantom credit / lost funds)." % callee)))

    return rows


# ============================================================================
# MOVE arm (minimal): `let _ = <coin op>` / `_ = <coin op>` discarding an
# abort-code / bool from a coin op.
# ============================================================================
_MOVE_DISCARD_RE = re.compile(
    r"(?m)^[ \t]*(?:let\s+)?_\s*=\s*(?P<rhs>[^\n;]*)")


def scan_move(text: str, rel: str):
    rows, seen = [], set()
    for m in _MOVE_DISCARD_RE.finditer(text):
        rhs = m.group("rhs")
        popen = rhs.find("(")
        if popen == -1:
            continue
        callee = _callee_name(rhs[:popen])
        if not _is_value_call(callee, rhs):
            continue
        off = m.start("rhs")
        line = _line_of_offset(text, off)
        key = ("move", line, callee)
        if key in seen:
            continue
        seen.add(key)
        rows.append(_mk_row(
            rel, "", line, "move-discard", callee, "move",
            _value_hint(callee, rhs), _excerpt(text, off), "medium",
            ("the return (abort-code / bool success) of the coin op `%s(...)` "
             "is discarded to `_`; a failed coin operation proceeds as if it "
             "succeeded (phantom credit / lost funds)." % callee)))
    return rows


# ============================================================================
# enclosing function name (best-effort)
# ============================================================================
_GO_FN_RE = re.compile(r"(?m)^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(")
_RS_FN_RE = re.compile(r"(?m)\bfn\s+([A-Za-z_]\w*)\s*[(<]")


def _enclosing_fn(text: str, off: int) -> str:
    best = ""
    for m in _GO_FN_RE.finditer(text):
        if m.start() > off:
            break
        best = m.group(1)
    return best


def _enclosing_fn_rs(text: str, off: int) -> str:
    best = ""
    for m in _RS_FN_RE.finditer(text):
        if m.start() > off:
            break
        best = m.group(1)
    return best


# ============================================================================
# row
# ============================================================================
def _mk_row(rel, fn, line, arm, callee, lang, value_hint, excerpt, severity,
            why):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, arm, (fn or "") + "|" + callee, line),
        "file": rel,
        "line": line,
        "function": fn,
        "lang": lang,
        "arm": arm,
        "callee": callee,
        "value_hint": value_hint,
        "discard_kind": arm,
        "guard_absent": True,
        "excerpt": excerpt,
        "severity": severity,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


# ============================================================================
# per-file dispatch
# ============================================================================
def scan_file(path: Path, rel: str, file_text: str = None):
    low = rel.lower()
    if not low.endswith(_EXTS):
        return []
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask(raw)
    if low.endswith(".go"):
        return scan_go(text, rel)
    if low.endswith(".rs"):
        return scan_rust(text, rel)
    if low.endswith(".move"):
        return scan_move(text, rel)
    return []


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
            if not low.endswith(_EXTS):
                continue
            if low.endswith("_test.go") or low.endswith("_test.rs") \
                    or low.startswith("test") or low.startswith("mock") \
                    or low == "tests.rs":
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
        "by_arm": _count(rows, "arm"),
        "by_lang": _count(rows, "lang"),
        "by_severity": _count(rows, "severity"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-4D discarded-fallible-result-on-a-value-path screen "
                    "(Go/Rust/Move, advisory)")
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
