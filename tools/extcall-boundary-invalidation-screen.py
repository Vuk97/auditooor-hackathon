#!/usr/bin/env python3
"""extcall-boundary-invalidation-screen.py - GEN-A4, the EXTERNAL-CALL BOUNDARY
STATE-INVALIDATION screen (Solidity primary; Rust + Go secondary).

GENERAL LOGIC / composition + trust-boundary class (impact-agnostic, never a bug
SHAPE). This is a TEMPORAL LOCAL-VALUE STALENESS invariant, DISTINCT from
CEI/reentrancy ordering:

  A LOCAL value/buffer is READ / CACHED from MUTABLE state (a balance, a storage
  slot, an array length, a map/collection element) BEFORE an untrusted boundary
  (an external call / token movement / callback / `.await` yield), then USED AFTER
  the boundary WITHOUT re-reading. The code trusts that the callee did not mutate
  the underlying state - but an untrusted callee (a token with a transfer hook /
  fee-on-transfer / rebasing, a re-entrant path, an awaited future, an interface
  callback, or simply a DIFFERENT actor between two calls) CAN mutate it. The
  cached local is then stale.

Why this is NOT the reentrancy/CEI lane (callback-reentrancy-composition.py /
cross-module-sibling-reentrancy.py / interproc-CEI / object-graph-xref):
  * CRC / CMSR / interproc-CEI enumerate STATE-WRITE ORDERING + reentrancy-GUARD
    PRESENCE: a write-before-settlement inside a callback window with no
    nonReentrant lock. They key on the WRITE side and on guard absence.
  * GEN-A4 keys on a LOCAL cached READ re-used stale across the boundary. It FIRES
    EVEN WITH A REENTRANCY GUARD PRESENT, because:
      - the guard need not cover the specific state the local mirrors (a token's
        OWN balanceOf is not protected by the contract's nonReentrant), OR
      - the mutation is by a DIFFERENT actor / the token contract itself during a
        fee-on-transfer / rebasing / hook transfer - no reentrancy at all, so the
        reentrancy screens are silent by construction.
    Canonical example: etherfi Liquifier.depositWithERC20 is `nonReentrant`, yet it
    CORRECTLY re-reads `balanceOf(this)` AFTER `safeTransferFrom` to measure the
    real amount received (stETH 1-2 wei rounding / rebase). A variant that cached
    the post-balance BEFORE the transfer and trusted the stale local would be a
    GEN-A4 defect that NO reentrancy tool flags (guard present, no CEI write).
  * object-graph-xref checks multi-handle cross-reference consistency (a spatial
    must-move-together relation), not a temporal cache-then-stale-use.

Pattern classes
---------------
Solidity (PRIMARY) - S_STALE_LOCAL_AFTER_EXTCALL:
  A local `v = <mutable-state-read>` (balanceOf / totalSupply / totalAssets /
  .length / address.balance / getReserves) is assigned BEFORE a boundary call
  (`.call`/`.delegatecall`/`.transfer`/`.send`/`.sendValue`/`safeTransfer*`/
  `transferFrom`/`onFlashLoan`/`onERC*Received`/`tokensReceived`/`functionCall*`)
  and `v` is READ AFTER the boundary with NO re-assignment of `v` between the
  boundary and the use. Deliberate before-snapshots (name contains
  before/prev/old/orig/initial/start/snapshot/prior/_pre/expected/min/max/cap/
  deadline/threshold/_0) are EXCLUDED - those are frozen by design.
  -> defect = stale-local-after-extcall.

Rust (SECONDARY) - R_BORROW_ACROSS_AWAIT:
  `let v = &<base>` / `<base>.iter()|.as_slice()|.get(..)|.len()` bound before an
  `.await`, `v` used after the `.await`, and the backing `<base>` is mutated
  (`.push`/`.insert`/`.remove`/`.clear`/`.truncate`/index-assign) after the bind -
  the reference/slice `v` is held ACROSS the yield while its backing changes.
  -> defect = borrow-across-await.

Go (SECONDARY) - G_STALE_VALUE_AFTER_CALL:
  `v := len(c)` / `c[k]` / `c.Get(..)` / `c.Load(..)` cached before a boundary
  (`.Call`/`.Invoke`/`.Callback`/`.Send`/`.Transfer`/`.Hook`/`.Execute`/
  `.Dispatch`/`callback(`/`cb(`), `v` used after with no reassignment between - the
  callee (interface/hook) may mutate the backing map/slice.
  -> defect = slice-backing-mutated.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False, and the tool exits 0 by default. The opt-in env
AUDITOOOR_EXTCALL_INVALIDATION_STRICT (or --strict) raises the exit code when a
fired row exists.

Excludes machine-generated (.pb.go/.pulsar.go + "DO NOT EDIT"), test, sim, vendored
code via the shared exclusion libs. Silent on other trees.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/extcall_boundary_invalidation_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar - tests/verify)
  --file <f>         scan a single .sol/.rs/.go file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a fired row exists
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

HYP_SCHEMA = "auditooor.extcall_boundary_invalidation_hypotheses.v1"
_SIDE_NAME = "extcall_boundary_invalidation_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_EXTCALL_INVALIDATION_STRICT"
_CAPABILITY = "GEN_A4"

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


def _load_codegen_sentinel():
    """Reuse declared-control-mutator-completeness-screen.py::_is_generated_source
    (the .go/.sol codegen sentinel) rather than re-inline the DO-NOT-EDIT logic."""
    tool = TOOLS_DIR / "declared-control-mutator-completeness-screen.py"
    try:
        spec = importlib.util.spec_from_file_location("_dc_screen_a4", tool)
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


_is_generated_source = _load_codegen_sentinel()

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "certora", "simulation", "simapp",
              "node", "testdata", "audits", "mocks"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|"
    r"fixtures|simulation|simapp|testdata)(/|$)")


# ============================================================================
# comment/string masking + function extraction (Solidity / Rust / Go)
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
    r"(?:function\s+([A-Za-z_]\w*))"                       # Solidity function foo
    r"|(?:modifier\s+([A-Za-z_]\w*))"                      # Solidity modifier m
    r"|(constructor|receive|fallback)\b"                   # Solidity special
    r"|(?:func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*))"         # Go func (recv) Foo
    r"|(?:(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*))"  # Rust fn
    r")")


def _fn_name(m):
    return (m.group(1) or m.group(2) or m.group(3) or m.group(4)
            or m.group(5) or "<anon>")


def _functions(lines):
    """Yield (name, decl_idx, sig_text, body_lines) for each brace-matched fn.
    body_lines is a list of (abs_idx, line) covering signature -> closing brace."""
    i, n = 0, len(lines)
    while i < n:
        m = _FN_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = _fn_name(m)
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


def _body_after_sig(body_lines) -> str:
    joined = "\n".join(l for _i, l in body_lines)
    brace = joined.find("{")
    return joined[brace + 1:] if brace >= 0 else joined


def _line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _stable_id(rel, fn, kind, var, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{kind}|{var}|{line}".encode())
    return h.hexdigest()[:16]


def _excerpt(text: str, off: int) -> str:
    ls = text.rfind("\n", 0, off) + 1
    le = text.find("\n", off)
    if le == -1:
        le = len(text)
    return text[ls:le].strip()[:180]


# ============================================================================
# shared: a local NAME that signals a DELIBERATE before-snapshot / bound
# (using it after a boundary is intended, not a staleness bug)
# ============================================================================
_SNAPSHOT_NAME_RE = re.compile(
    r"(?i)(before|prev|previous|old|orig|initial|_init|start|snapshot|snap|"
    r"prior|_pre\b|pre_|expected|minimum|maximum|_min\b|_max\b|cap\b|floor|"
    r"ceil|deadline|threshold|_0\b|baseline_?snapshot|limit)")


def _is_snapshot_name(name: str) -> bool:
    return bool(_SNAPSHOT_NAME_RE.search(name))


def _uses_after(body: str, name: str, after_off: int, upto_off: int = None):
    """Return offset of the first READ use of `name` strictly after `after_off`
    (and before upto_off if given), or None. A use where the next non-space char
    is a lone '=' (assignment LHS) is NOT a read; ':=' / '==' / '+=' etc excluded
    from being treated as reassignment here (handled by _reassigned_between)."""
    upto = upto_off if upto_off is not None else len(body)
    for m in re.finditer(r"\b" + re.escape(name) + r"\b", body):
        o = m.start()
        if o <= after_off or o >= upto:
            continue
        tail = body[m.end():m.end() + 3]
        st = tail.lstrip()
        # LHS of a plain assignment `name =` (not ==, +=, etc.) -> not a read
        if st[:1] == "=" and st[1:2] != "=":
            continue
        return o
    return None


def _stmt_end(body: str, off: int) -> int:
    """Offset just past the `;` that terminates the statement containing/at `off`
    (so a value passed as an ARGUMENT to the boundary call - consumed BEFORE the
    call returns - is not mistaken for a stale post-call read). Falls back to a
    newline, then to `off`."""
    semi = body.find(";", off)
    if semi != -1:
        return semi + 1
    nl = body.find("\n", off)
    return (nl + 1) if nl != -1 else off


def _reassigned_between(body: str, name: str, lo: int, hi: int) -> bool:
    """True if `name` is re-assigned (plain `=` or Go `:=`) anywhere in (lo, hi] -
    i.e. the code RE-READ fresh state into it after the boundary (benign)."""
    seg_start = lo
    for m in re.finditer(r"\b" + re.escape(name) + r"\b", body):
        o = m.start()
        if o <= seg_start or o > hi:
            continue
        tail = body[m.end():m.end() + 3].lstrip()
        if tail[:2] == ":=":
            return True
        if tail[:1] == "=" and tail[1:2] != "=":
            return True
    return False


# ============================================================================
# Solidity arm (PRIMARY): S_STALE_LOCAL_AFTER_EXTCALL
# ============================================================================
_SOL_STATE_READ_RE = re.compile(
    r"\.balanceOf\s*\(|\.totalSupply\s*\(|\.totalAssets\s*\(|"
    r"\bgetReserves\s*\(|\.getReserves\s*\(|\.length\b|"
    r"(?<![\w.])address\s*\([^)]*\)\s*\.balance\b|"
    r"\)\s*\.balance\b|\.convertToAssets\s*\(|\.convertToShares\s*\(")
_SOL_BOUNDARY_RE = re.compile(
    r"\.(?:call|delegatecall|staticcall)\s*[({]"
    r"|\.(?:transfer|send|sendValue)\s*\("
    r"|\.(?:safeTransfer|safeTransferFrom|transferFrom|safeApprove)\s*\("
    r"|\.(?:onFlashLoan|onMorpho\w*|onERC\d*Received|tokensReceived|"
    r"onTokenTransfer|receiveFlashLoan|uniswapV\dCall|hook\w*)\s*\("
    r"|\.functionCall\w*\s*\(")
# a local assignment (optionally typed) capturing name + full RHS to `;`
_SOL_ASSIGN_RE = re.compile(
    r"(?:\b(?:uint\d*|int\d*|address(?:\s+payable)?|bytes\d*|bool)\b\s+)?"
    r"([A-Za-z_]\w*)\s*(?<![=!<>+\-*/%&|^])=(?!=)\s*([^;]+);")


def _scan_sol_fn(rel, name, decl_idx, body, rows):
    boundaries = [m.start() for m in _SOL_BOUNDARY_RE.finditer(body)]
    if not boundaries:
        return
    first_b = min(boundaries)
    last_b = max(boundaries)
    for m in _SOL_ASSIGN_RE.finditer(body):
        var, rhs = m.group(1), m.group(2)
        cache_off = m.start(1)
        if _is_snapshot_name(var):
            continue
        if not _SOL_STATE_READ_RE.search(rhs):
            continue
        # need a boundary AFTER the cache read
        after_bounds = [b for b in boundaries if b > m.end()]
        if not after_bounds:
            continue
        b0 = min(after_bounds)
        # a use consumed as an ARGUMENT to the boundary call itself is passed
        # BEFORE the call returns -> only count reads after the call statement.
        thresh = _stmt_end(body, b0)
        use_off = _uses_after(body, var, thresh)
        if use_off is None:
            continue
        # benign if the local was RE-READ (reassigned) between boundary and use
        if _reassigned_between(body, var, b0, use_off):
            continue
        rows.append(_mk_row(
            rel, name, _line_of_offset(body, cache_off) + decl_idx, "solidity",
            "S_STALE_LOCAL_AFTER_EXTCALL", var,
            _excerpt(body, b0)[:80], "stale-local-after-extcall",
            _excerpt(body, cache_off),
            f"local `{var}` caches a mutable-state read "
            f"(`{rhs.strip()[:60]}`) BEFORE an untrusted boundary call, then is "
            f"read AFTER the call with no re-read - if the callee (a token "
            f"hook / fee-on-transfer / rebase, a re-entrant path, or a different "
            f"actor) mutated the mirrored state, `{var}` is stale. This fires "
            f"independent of any reentrancy guard because the guard need not "
            f"cover the token's own balance and the mutation may be non-reentrant."
        ))
        break  # one row per function is enough to flag the fn (low-spray)


# ============================================================================
# Rust arm (SECONDARY): R_BORROW_ACROSS_AWAIT
# ============================================================================
_RS_BIND_RE = re.compile(
    r"\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]+)?=\s*"
    r"&?\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*"
    r"(?:\.(iter|as_slice|as_ref|get|len|first|last)\s*\(|;|\.)")
_RS_AWAIT_RE = re.compile(r"\.await\b")


def _rs_base_ident(expr: str) -> str:
    # leading receiver ident of a dotted expr, e.g. self.buf -> self.buf
    return expr.strip()


def _scan_rust_fn(rel, name, decl_idx, body, rows):
    awaits = [m.start() for m in _RS_AWAIT_RE.finditer(body)]
    if not awaits:
        return
    for m in _RS_BIND_RE.finditer(body):
        var = m.group(1)
        base = m.group(2)
        bind_off = m.start()
        # must be a reference / slice / element borrow (group3 present) OR a `&`
        is_borrow = m.group(3) is not None or body[m.start():m.end()].find("&") >= 0
        if not is_borrow:
            continue
        if _is_snapshot_name(var):
            continue
        after_awaits = [a for a in awaits if a > m.end()]
        if not after_awaits:
            continue
        a0 = min(after_awaits)
        use_off = _uses_after(body, var, a0)
        if use_off is None:
            continue
        # require the backing collection to be MUTATED after the bind (else the
        # held reference is benign / read-only)
        base_last = base.split(".")[-1]
        mut_re = re.compile(
            r"\b" + re.escape(base) + r"\s*\.\s*"
            r"(push|insert|remove|clear|truncate|retain|swap_remove|pop|extend|"
            r"sort|drain|resize|append)\s*\("
            r"|\b" + re.escape(base) + r"\s*\[[^\]]+\]\s*=")
        if not mut_re.search(body[bind_off:]):
            continue
        rows.append(_mk_row(
            rel, name, _line_of_offset(body, bind_off) + decl_idx, "rust",
            "R_BORROW_ACROSS_AWAIT", var,
            _excerpt(body, a0)[:80], "borrow-across-await",
            _excerpt(body, bind_off),
            f"reference/slice `{var}` borrows `{base}` and is held ACROSS a "
            f"`.await` yield, then used after the await while `{base}` is mutated "
            f"(push/insert/remove/index-assign) - the awaited future can run "
            f"between the borrow and the use, leaving `{var}` pointing at stale / "
            f"reallocated backing (borrow-across-await staleness)."))
        break


# ============================================================================
# Go arm (SECONDARY): G_STALE_VALUE_AFTER_CALL
# ============================================================================
_GO_CACHE_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*:=\s*("
    r"len\s*\([^)]*\)"
    r"|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\s*\[[^\]]+\]"
    r"|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.(?:Get|Load|Peek|Front|Back)\s*\("
    r")")
_GO_BOUNDARY_RE = re.compile(
    r"\.(?:Call|Invoke|Callback|Send|Transfer|Hook|Execute|Dispatch|"
    r"OnRecv\w*|OnAcknowledgement\w*|Emit|Notify|Handle)\s*\("
    r"|\bcallback\s*\(|\bcb\s*\(")


def _scan_go_fn(rel, name, decl_idx, body, rows):
    boundaries = [m.start() for m in _GO_BOUNDARY_RE.finditer(body)]
    if not boundaries:
        return
    for m in _GO_CACHE_RE.finditer(body):
        var = m.group(1)
        rhs = m.group(2)
        cache_off = m.start(1)
        if _is_snapshot_name(var):
            continue
        after_bounds = [b for b in boundaries if b > m.end()]
        if not after_bounds:
            continue
        b0 = min(after_bounds)
        thresh = _stmt_end(body, b0)
        use_off = _uses_after(body, var, thresh)
        if use_off is None:
            continue
        if _reassigned_between(body, var, b0, use_off):
            continue
        rows.append(_mk_row(
            rel, name, _line_of_offset(body, cache_off) + decl_idx, "go",
            "G_STALE_VALUE_AFTER_CALL", var,
            _excerpt(body, b0)[:80], "slice-backing-mutated",
            _excerpt(body, cache_off),
            f"local `{var}` caches a map/slice/len read (`{rhs.strip()[:50]}`) "
            f"before an interface/callback/external boundary call, then is used "
            f"after with no re-read - the callee (hook / interface method) can "
            f"mutate the backing map or slice, leaving `{var}` stale."))
        break


# ============================================================================
# row + summary
# ============================================================================
def _mk_row(rel, fn, line, lang, kind, cached_value, boundary_call, defect,
            excerpt, why):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, fn, kind, cached_value, line),
        "file": rel,
        "line": line,
        "function": fn,
        "context": fn,
        "lang": lang,
        "pattern_id": kind,
        "cached_value": cached_value,
        "boundary_call": boundary_call,
        "defect": defect,
        "excerpt": excerpt,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    low = rel.lower()
    if low.endswith(".rs"):
        lang = "rust"
    elif low.endswith(".go"):
        lang = "go"
    else:
        lang = "solidity"
    lines = text.split("\n")
    rows = []
    for name, decl_idx, sig, body_lines in _functions(lines):
        body = _body_after_sig(body_lines)
        if lang == "solidity":
            _scan_sol_fn(rel, name, decl_idx, body, rows)
        elif lang == "rust":
            _scan_rust_fn(rel, name, decl_idx, body, rows)
        else:
            _scan_go_fn(rel, name, decl_idx, body, rows)
    return rows


def _iter_source_files(root: Path, workspace: Path = None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not (low.endswith(".sol") or low.endswith(".rs")
                    or low.endswith(".go")):
                continue
            if (low.endswith("_test.go") or low.endswith(".t.sol")
                    or low.endswith("_test.rs")):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            rel = str(p)
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
        "candidates": len(rows),
        "fired": len(fired),
        "by_pattern": _count(rows, "pattern_id"),
        "by_lang": _count(rows, "lang"),
        "by_defect": _count(rows, "defect"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-A4 external-call boundary state-invalidation screen "
                    "(Solidity primary; Rust + Go secondary; advisory)")
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
