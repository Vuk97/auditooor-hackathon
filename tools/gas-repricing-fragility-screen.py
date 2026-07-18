#!/usr/bin/env python3
"""gas-repricing-fragility-screen.py - GEN-EL5, the GAS-METERING / OPCODE-
REPRICING FRAGILITY screen (enforcement-layer = consensus-gas).

Solidity-primary (transfer/send stipend, fixed-gas call, gasleft() threshold,
gas-bounded loop, 63/64-forward). Vyper (send / raw_call gas=) + Go/Cosmos
(ctx.GasMeter() threshold, hard-coded GasConfig cost) secondary.

GENERAL LOGIC (impact-agnostic consensus-layer class, never a numeric-value
SHAPE). A safety or correctness property must NOT rest on a HARD-CODED gas
magic-number, because a consensus hardfork that REPRICES opcodes shifts the real
cost and INVALIDATES the argument. This is not hypothetical:

  * EIP-1884 (Istanbul) raised SLOAD 200->800, BALANCE / EXTCODEHASH costs -
    RETROACTIVELY broke the `addr.transfer(x)` 2300-gas-stipend "reentrancy is
    impossible" argument for recipients that SLOAD in their receive() hook.
  * EIP-2929 (Berlin) made the FIRST (cold) SLOAD / *CALL / EXT* access far more
    expensive.
  * EIP-3529 (London) removed most gas refunds.

FIRE when a gas constant is LOAD-BEARING for a safety argument:
  (1) transfer-stipend: `addr.transfer(x)` / `addr.send(x)` (native ETH, single
      arg) where addr is a STORED / non-fresh address - the 2300-stipend used as
      implicit reentrancy protection (EIP-1884 already broke this once);
  (2) fixed-gas-call: `call{gas: N}(...)` whose sufficiency is ASSUMED;
  (3) gasleft-threshold: `require(gasleft() > CONST)` / `if (gasleft() < CONST)`
      guarding a state transition / retry / refund;
  (4) gas-bounded-loop: a loop whose termination rests on a per-iteration gas
      cost (`while (gasleft() > CONST)`);
  (5) 63-64-forward: the EIP-150 63/64 gas-forwarding rule assumed for a subcall
      re-entry guard.

FP-CONTROL (load-bearing, do NOT spray): the STRONG signal is the gas constant
being LOAD-BEARING FOR A SAFETY ARGUMENT.
  * A bare `payable(msg.sender).transfer(x)` withdraw to a FRESH msg.sender is
    LOW-signal -> emitted at severity='low' (or when a nonReentrant guard is
    already present).
  * A `.transfer` / `.send` to a STORED state-var / immutable / non-msg.sender
    payee is the STRONG structural case -> severity='medium'.
  * ERC20 `token.transfer(to, amt)` (TWO args) and `transferFrom` are NOT native
    stipend calls - suppressed (only single-arg native transfer/send fires).
  * SafeERC20 `.safeTransfer` never matches (method must be transfer/send).

DEDUP / distinctness (per dispatch brief):
  * go-unbounded-alloc-noprogress / rust-eager-alloc-nomax screen ALLOC-SIZE DoS
    (unbounded memory), NOT opcode-repricing of a gas constant.
  * general reentrancy detectors check a MISSING guard, not the gas-stipend-AS-
    guard fragility.
  * unbounded-loop detectors check a MISSING bound, not a repricing-sensitive gas
    bound.
  GEN-EL5 = the safety-argument-rests-on-a-gas-magic-number JOIN; if a site
  reduces to one of the above it is dropped as overlap.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False; the tool exits 0 by default. The opt-in env
AUDITOOOR_GAS_REPRICING_FRAGILITY_STRICT (or --strict) raises the exit code when
a fired row exists.

Excludes machine-generated (.pb.go/.pulsar.go + "DO NOT EDIT"), test, mock, sim
and vendored code via the shared exclusion libs.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/
                     gas_repricing_fragility_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single .sol/.vy/.go file, print rows as JSON
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

HYP_SCHEMA = "auditooor.gas_repricing_fragility_hypotheses.v1"
_SIDE_NAME = "gas_repricing_fragility_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_GAS_REPRICING_FRAGILITY_STRICT"
_CAPABILITY = "GEN_EL5"

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
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "certora", "simulation", "testdata",
              "mocks", "mock", "artifacts", "chimera_harnesses"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|testutil|testonly|testhelper|test_fixtures|mock|mocks|"
    r"benches|benchmarks?|examples|fixtures|simulation|simapp|testdata|poc|"
    r"chimera_harnesses)(/|$)")
_CODEGEN_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)


# ============================================================================
# comment / string masking (Solidity + Go share C-ish comments; Vyper uses '#').
# ============================================================================
def _mask_comments(text: str, lang: str) -> str:
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = False
    quote = ""
    hash_line = lang == "vyper"
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
        elif c in ('"', "'"):
            in_str = True
            quote = c
            out.append(" ")
            i += 1
        elif hash_line and c == "#":
            in_line = True
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


def _stable_id(rel, kind, subject, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{kind}|{subject}|{line}".encode())
    return h.hexdigest()[:16]


def _lang_of(rel: str) -> str:
    low = rel.lower()
    if low.endswith(".vy"):
        return "vyper"
    if low.endswith(".go"):
        return "go"
    return "solidity"


# ============================================================================
# enclosing-function attribution (Solidity `function`, Go `func`, Vyper `def`).
# ============================================================================
_FN_DECL_RE = re.compile(
    r"(?:^|\n)\s*(?:"
    r"function\s+([A-Za-z_]\w*)"            # Solidity function foo
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("  # Go func / method
    r"|def\s+([A-Za-z_]\w*)"                # Vyper def foo
    r"|(fallback)\s*\("                     # Solidity fallback()
    r"|(receive)\s*\()")                    # Solidity receive()


def _enclosing_function(text: str, off: int) -> str:
    best = "<file>"
    for m in _FN_DECL_RE.finditer(text):
        if m.start() > off:
            break
        best = next((g for g in m.groups() if g), best)
    return best


def _paren_span(text: str, open_idx: int):
    """Return (inner_string, close_idx) for a '(' at text[open_idx]. Handles
    nested parens. close_idx == -1 if unbalanced."""
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
    return text[open_idx + 1:], -1


def _top_level_args(inner: str):
    """Split a call-arg string on top-level commas (ignoring nested () [] {})."""
    args = []
    depth = 0
    cur = []
    for ch in inner:
        if ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail or args:
        args.append(tail)
    return args


# ============================================================================
# SOLIDITY arms
# ============================================================================
# native single-arg .transfer / .send:  RECV.transfer(  /  RECV.send(
_XFER_HEAD_RE = re.compile(
    r"(?P<recv>payable\s*\(\s*[^;()]*\)"          # payable(<expr>)
    r"|address\s*\(\s*[^;()]*\)"                    # address(<expr>)
    r"|[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*"       # ident chain a.b.c
    r"(?:\s*\[\s*[^\];]*\])?)"                      # optional [index]
    r"\s*\.\s*(?P<meth>transfer|send)\s*\(")

# fixed-gas external call: .call{...gas: N...}(  /  {gas: N}
_GAS_OPT_RE = re.compile(
    r"\{[^{}]*\bgas\s*:\s*(?P<g>[0-9][0-9_]*|[A-Za-z_]\w*)[^{}]*\}")
_CALLISH_RE = re.compile(r"\.\s*(?:call|delegatecall|staticcall|callcode)\s*\{")

# gasleft() threshold gate:  gasleft() <cmp> N  or  N <cmp> gasleft()
_GASLEFT_CMP_RE = re.compile(
    r"gasleft\s*\(\s*\)\s*(?P<op><=?|>=?)\s*(?P<n>[0-9][0-9_]*|[A-Za-z_]\w*)"
    r"|(?P<n2>[0-9][0-9_]*|[A-Za-z_]\w*)\s*(?P<op2><=?|>=?)\s*gasleft\s*\(\s*\)")
# 63/64 forwarding assumption:  gasleft() * 63 / 64  (or /64, *63)
_SIXTY_THREE_RE = re.compile(
    r"gasleft\s*\(\s*\)\s*[*/]\s*6[34]\b|\b6[34]\s*[*/]\s*gasleft\s*\(\s*\)")

_REFUND_HINT = re.compile(r"(?i)refund")
_RETRY_HINT = re.compile(r"(?i)retry|reattempt|re-?execute|redeliver")
_LOOP_HEAD_RE = re.compile(r"\b(while|for)\s*\(")
_NONREENTRANT_RE = re.compile(r"(?i)nonReentrant|noReentrancy|reentrancyGuard")


def _in_loop_condition(text: str, off: int) -> bool:
    """True if the gasleft() at off is inside a while/for loop HEADER condition."""
    # scan backwards to the nearest '(' that opens a while/for header on the
    # same statement, without crossing a ';' or '{'.
    depth = 0
    i = off
    while i > 0:
        ch = text[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                # found the opening paren of the enclosing call/condition
                pre = text[max(0, i - 6):i]
                return bool(re.search(r"\b(while|for)\s*$", pre))
            depth -= 1
        elif ch in ";{}" and depth == 0:
            return False
        i -= 1
    return False


def _scan_solidity(text: str, rel: str, rows):
    # --- (1) transfer / send stipend ----------------------------------------
    seen = set()
    for m in _XFER_HEAD_RE.finditer(text):
        recv = re.sub(r"\s+", "", m.group("recv"))
        meth = m.group("meth")
        open_idx = m.end() - 1
        inner, close = _paren_span(text, open_idx)
        if close == -1:
            continue
        args = _top_level_args(inner)
        # native ETH transfer/send take EXACTLY ONE arg (the value). ERC20
        # transfer(to, amt) has two -> suppressed here.
        if len(args) != 1:
            continue
        # skip a bare `token.transfer(x)` that is actually a 1-arg custom call is
        # indistinguishable; but a single-arg .transfer/.send on an address is
        # the native form by Solidity typing. Suppress obvious non-address recv
        # (e.g. a mapping value assign) is not needed - recv is address-shaped.
        off = m.start()
        fn = _enclosing_function(text, off)
        line = _line_of_offset(text, off)
        fresh_sender = "msg.sender" in recv
        # a nonReentrant guard in the enclosing fn means the stipend is NOT the
        # reentrancy defense -> lower the signal (still a dos-liveness note).
        fn_body = _enclosing_fn_body(text, off)
        guarded = bool(_NONREENTRANT_RE.search(fn_body))
        if fresh_sender or guarded:
            sev = "low"
            lb = "dos-liveness" if guarded else "reentrancy-protection"
        else:
            sev = "medium"
            lb = "reentrancy-protection"
        key = (recv, meth, line)
        if key in seen:
            continue
        seen.add(key)
        rows.append(_mk_row(
            rel, fn, line, "solidity", "transfer-stipend", lb, "2300",
            _excerpt(text, off), sev,
            _why_transfer(recv, meth, fresh_sender, guarded)))

    # --- (2) fixed-gas external call ----------------------------------------
    for cm in _CALLISH_RE.finditer(text):
        # the options block starts at the '{' the call regex ended on
        brace_idx = cm.end() - 1
        block, bclose = _brace_span(text, brace_idx)
        if bclose == -1:
            continue
        gm = re.search(r"\bgas\s*:\s*([0-9][0-9_]*|[A-Za-z_]\w*)", block)
        if not gm:
            continue
        gconst = gm.group(1)
        # a `gas: gasleft()`-ish forward is not a hard-coded magic number.
        if gconst in ("gasleft",):
            continue
        off = cm.start()
        fn = _enclosing_function(text, off)
        line = _line_of_offset(text, off)
        rows.append(_mk_row(
            rel, fn, line, "solidity", "fixed-gas-call", "dos-liveness",
            gconst, _excerpt(text, off), "medium",
            f"a fixed-gas external call forwards a hard-coded `gas: {gconst}` "
            f"whose sufficiency is ASSUMED; an EIP-2929/1884-style repricing "
            f"raises the callee's real cost and makes the sub-call revert "
            f"(out-of-gas) - bricking the path (DoS) or silently dropping it if "
            f"the return value is unchecked."))

    # --- (3) gasleft() threshold gate + (4) gas-bounded loop ----------------
    for gm in _GASLEFT_CMP_RE.finditer(text):
        gconst = gm.group("n") or gm.group("n2") or ""
        # ignore comparisons against 0 (a liveness sanity check, not a magic
        # cost threshold).
        if gconst in ("0",):
            continue
        off = gm.start()
        fn = _enclosing_function(text, off)
        line = _line_of_offset(text, off)
        gl_off = text.find("gasleft", off)
        loop = _in_loop_condition(text, gl_off if gl_off >= 0 else off)
        fn_body = _enclosing_fn_body(text, off)
        if loop:
            construct, lb = "gas-bounded-loop", "dos-liveness"
            why = (
                f"a loop's termination rests on `gasleft()` vs a hard-coded "
                f"`{gconst}` per-iteration budget; an EIP-2929/1884-style "
                f"opcode repricing shifts the per-iteration cost, so the loop "
                f"bound (and its progress/DoS guarantee) is INVALIDATED by a "
                f"hardfork.")
        else:
            construct = "gasleft-threshold"
            if _REFUND_HINT.search(fn_body):
                lb = "refund"
            elif _RETRY_HINT.search(fn_body):
                lb = "retry"
            else:
                lb = "dos-liveness"
            why = (
                f"a state transition is gated on `require/if gasleft() {gm.group(0).strip()}` "
                f"against a hard-coded `{gconst}`; the gate assumes a FIXED "
                f"downstream gas cost - an EIP-2929/1884/3529 repricing shifts "
                f"the real cost and lets the gate pass/fail incorrectly "
                f"(griefing a {lb} path or bricking the transition).")
        rows.append(_mk_row(
            rel, fn, line, "solidity", construct, lb, gconst,
            _excerpt(text, off), "medium", why))

    # --- (5) 63/64 forwarding assumption ------------------------------------
    for sm in _SIXTY_THREE_RE.finditer(text):
        off = sm.start()
        fn = _enclosing_function(text, off)
        line = _line_of_offset(text, off)
        rows.append(_mk_row(
            rel, fn, line, "solidity", "63-64-forward", "reentrancy-protection",
            "63/64", _excerpt(text, off), "low",
            "an explicit EIP-150 63/64 gas-forwarding computation is used in a "
            "control decision (often a re-entry / relay budget guard); the "
            "63/64 rule and the residual gas it leaves are consensus constants "
            "that a future repricing can shift, invalidating the assumption."))


def _enclosing_fn_body(text: str, off: int) -> str:
    """Return the enclosing brace-delimited function body around off (best
    effort, brace-balanced from the nearest preceding 'function'/'func')."""
    start = -1
    for m in re.finditer(r"\b(?:function|func)\b", text):
        if m.start() > off:
            break
        start = m.start()
    if start < 0:
        return text[max(0, off - 200):off + 200]
    brace = text.find("{", start)
    if brace < 0 or brace > off + 4000:
        return text[start:off + 200]
    body, close = _brace_span(text, brace)
    if close == -1 or close < off:
        return text[start:off + 400]
    return text[start:close + 1]


def _brace_span(text: str, open_idx: int):
    depth = 0
    n = len(text)
    i = open_idx
    while i < n:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i
        i += 1
    return text[open_idx + 1:], -1


def _why_transfer(recv, meth, fresh_sender, guarded):
    base = (
        f"`{recv}.{meth}(...)` forwards only the hard-coded 2300-gas stipend. "
        f"The stipend is a CONSENSUS constant: EIP-1884 (Istanbul) already "
        f"raised SLOAD/BALANCE costs and RETROACTIVELY broke this exact "
        f"'2300 gas => no reentrancy / recipient always succeeds' argument. ")
    if fresh_sender:
        return base + (
            "Here the payee is a FRESH msg.sender withdraw (LOW signal), but a "
            "future repricing can still brick a smart-contract-wallet recipient "
            "(DoS on withdrawal).")
    if guarded:
        return base + (
            "A nonReentrant guard is present so the stipend is not the "
            "reentrancy defense, but the fixed 2300 gas can still brick a "
            "contract recipient after a repricing (dos-liveness).")
    return base + (
        "The payee is a STORED / non-msg.sender address: the 2300 stipend is "
        "load-bearing as implicit reentrancy protection AND as the delivery "
        "guarantee - a repricing either re-enables reentrancy or bricks the "
        "transfer. Prefer `(bool ok,) = addr.call{value:x}(\"\")` + a "
        "reentrancy guard.")


# ============================================================================
# VYPER arms (secondary)
# ============================================================================
_VY_SEND_RE = re.compile(r"(?<![\w.])send\s*\(\s*([^,()]+)\s*,")
_VY_RAWCALL_GAS_RE = re.compile(
    r"raw_call\s*\([^)]*?\bgas\s*=\s*([0-9][0-9_]*|[A-Z_][A-Z0-9_]*)")


def _scan_vyper(text: str, rel: str, rows):
    for m in _VY_SEND_RE.finditer(text):
        off = m.start()
        line = _line_of_offset(text, off)
        fn = _enclosing_function(text, off)
        recv = m.group(1).strip()
        sev = "low" if "msg.sender" in recv else "medium"
        rows.append(_mk_row(
            rel, fn, line, "vyper", "transfer-stipend", "reentrancy-protection",
            "2300", _excerpt(text, off), sev,
            f"Vyper `send({recv}, ...)` forwards only the fixed 2300-gas "
            f"stipend (same consensus constant EIP-1884 already broke); a "
            f"repricing can re-enable reentrancy or brick a contract recipient. "
            f"Prefer raw_call with an explicit, adequate gas + a reentrancy "
            f"guard."))
    for m in _VY_RAWCALL_GAS_RE.finditer(text):
        off = m.start()
        line = _line_of_offset(text, off)
        fn = _enclosing_function(text, off)
        rows.append(_mk_row(
            rel, fn, line, "vyper", "fixed-gas-call", "dos-liveness",
            m.group(1), _excerpt(text, off), "medium",
            f"a Vyper `raw_call(..., gas={m.group(1)})` pins a hard-coded gas "
            f"forward whose sufficiency is assumed - an opcode repricing raises "
            f"the callee cost and reverts the sub-call (DoS)."))


# ============================================================================
# GO / COSMOS arm (secondary): ctx.GasMeter() threshold vs a hard-coded cost, or
# a keeper loop gated on remaining gas.
# ============================================================================
_GO_GASMETER_CMP_RE = re.compile(
    r"GasMeter\s*\(\s*\)\s*\.\s*(?:GasConsumed|GasRemaining|Limit)\s*\(\s*\)"
    r"\s*(?:<=?|>=?)\s*(?:uint64\s*\(\s*)?([0-9][0-9_]+)")
_GO_CONSUMEGAS_MAGIC_RE = re.compile(
    r"ConsumeGas\s*\(\s*(?:uint64\s*\(\s*)?([0-9]{3,})\b")


def _scan_go(text: str, rel: str, rows):
    for m in _GO_GASMETER_CMP_RE.finditer(text):
        off = m.start()
        line = _line_of_offset(text, off)
        fn = _enclosing_function(text, off)
        rows.append(_mk_row(
            rel, fn, line, "go", "gasleft-threshold", "dos-liveness",
            m.group(1), _excerpt(text, off), "medium",
            f"a Cosmos keeper compares `ctx.GasMeter()` against a hard-coded "
            f"`{m.group(1)}`; a governance/upgrade GasConfig change (or an EVM "
            f"module opcode repricing) shifts the real cost, so this gas gate's "
            f"liveness/DoS guarantee is invalidated by a param change."))
    for m in _GO_CONSUMEGAS_MAGIC_RE.finditer(text):
        off = m.start()
        line = _line_of_offset(text, off)
        fn = _enclosing_function(text, off)
        # only report inside a loop-ish context to keep targeted.
        pre = text[max(0, off - 200):off]
        if not re.search(r"\b(for|range)\b", pre):
            continue
        rows.append(_mk_row(
            rel, fn, line, "go", "gas-bounded-loop", "dos-liveness",
            m.group(1), _excerpt(text, off), "low",
            f"a keeper loop charges a hard-coded `ConsumeGas({m.group(1)})` per "
            f"iteration; if the batch size / block gas budget was tuned to this "
            f"fixed cost, a GasConfig change shifts the achievable batch and can "
            f"brick the loop (DoS)."))


# ============================================================================
# row builder
# ============================================================================
def _mk_row(rel, fn, line, lang, gas_construct, load_bearing_for, gas_const,
            excerpt, severity, why):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, gas_construct, fn + "|" + gas_const, line),
        "file": rel,
        "line": line,
        "function": fn,
        "lang": lang,
        "gas_construct": gas_construct,
        "load_bearing_for": load_bearing_for,
        "gas_const": gas_const,
        "excerpt": excerpt,
        "severity": severity,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


# ============================================================================
# per-file scan
# ============================================================================
def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    lang = _lang_of(rel)
    text = _mask_comments(raw, lang)
    rows = []
    if lang == "solidity":
        _scan_solidity(text, rel, rows)
    elif lang == "vyper":
        _scan_vyper(text, rel, rows)
    elif lang == "go":
        _scan_go(text, rel, rows)
    return rows


# ============================================================================
# tree walk + sidecar
# ============================================================================
def _iter_source_files(root: Path, workspace: Path = None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not (low.endswith(".sol") or low.endswith(".vy")
                    or low.endswith(".go")):
                continue
            if low.endswith(".t.sol") or low.endswith(".s.sol") \
                    or low.endswith("_test.go"):
                continue
            if _TEST_HINT.search(f) or low.startswith("mock") \
                    or low.startswith("test"):
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
        "gas_sites": len(rows),
        "fired": len(fired),
        "by_gas_construct": _count(rows, "gas_construct"),
        "by_load_bearing_for": _count(rows, "load_bearing_for"),
        "by_severity": _count(rows, "severity"),
        "by_lang": _count(rows, "lang"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-EL5 gas-metering / opcode-repricing fragility screen "
                    "(Solidity + Vyper + Go, advisory)")
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
