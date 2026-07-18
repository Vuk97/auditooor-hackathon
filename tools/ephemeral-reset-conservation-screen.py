#!/usr/bin/env python3
"""ephemeral-reset-conservation-screen.py - GEN-A3, the EPHEMERAL-STORE
RESET-CONSERVATION + WRITE-TIER FIDELITY screen (Solidity primary, Go secondary).

GENERAL LOGIC / coupled-state TRUST-ENFORCEMENT class (impact-agnostic, never a
bug SHAPE). A MUST-RESET-BETWEEN-SCOPES store - EIP-1153 transient storage
(`tstore`/`tload`, the `transient` keyword), a reentrancy-guard flag
(`_status`/`_locked`/`nonReentrant`), a tx-scoped cache/accumulator - carries a
lifecycle invariant:

  (1) RESET-DOMINANCE : the reset-to-default write must dominate EVERY function
      exit + revert/early-return edge. A path that SETS the flag to its engaged
      value and then early-`return`s (or never resets at all) WITHOUT restoring
      the default leaves cross-tx / cross-call residue - the guard stays engaged
      or a stale cache value is trusted in the next scope.
  (2) WRITE-TIER FIDELITY : the SET and the RESET must use the SAME storage tier.
      A transient slot (`tstore`/EIP-1153) that is reset via a persistent
      `sstore` (or the reverse) POISONS cross-tx state (the TSTORE-poison
      delete-mis-emits-sstore class).

The enforcement point is: "a delegated ephemeral store trusts it was reset before
the next scope". A scoped store whose reset does NOT dominate all exit/revert
edges, OR whose set/reset use mismatched tiers, is flagged (advisory,
verdict=needs-fuzz).

Pattern classes
---------------
Solidity (PRIMARY):
  * S_GUARD_RESET_MISSING : a reentrancy-guard / lock flag (name-heuristic
      `_status`/`lock(ed)`/`entered`/`reentran*`/`mutex`/`guard`) is SET to an
      ENGAGED value (`true`/`2`/`_ENTERED`/`LOCKED`) somewhere in the file but is
      NEVER reset to its DEFAULT (`false`/`0`/`1`/`_NOT_ENTERED`, or `delete`)
      anywhere in the file -> the guard stays permanently engaged.
      -> defect = reset-not-dominating-exit, store_kind = reentrancy-flag.
  * S_GUARD_EARLY_RETURN : within ONE function/modifier the flag is SET engaged
      and a DEFAULT reset exists later, but a standalone `return` sits between the
      set and that reset -> the early-return edge bypasses the reset.
      -> defect = reset-not-dominating-exit, store_kind = reentrancy-flag.
  * S_TSTORE_RESET_MISSING : `tstore(slot, <nonzero>)` (or `.tstore(true)`) with
      no `tstore(slot, 0)` / `.tstore(false)` reset in the file -> transient
      residue survives for the rest of the tx (cross-call within tx).
      -> defect = reset-not-dominating-exit, store_kind = transient.
  * S_TIER_MISMATCH : the SAME assembly slot expression is written by BOTH
      `tstore(slot, ...)` and `sstore(slot, ...)` -> a transient set reset by a
      persistent store (or vice versa) poisons cross-tx state.
      -> defect = tier-mismatch-set-vs-reset, store_kind = transient.
Go (SECONDARY):
  * G_CACHE_EARLY_RETURN : a tx/thread-scoped cache field (name-heuristic
      `cache`/`scoped`/`pending`/`current`/`active`/`txCtx`/`guard`/`lock`) is
      assigned a non-default value and later reset to nil/default in the SAME
      function, but a `return` sits between the set and the reset (missing a
      `defer`ed reset) -> an error/early-return path leaks the scoped value.
      -> defect = reset-not-dominating-exit, store_kind = tx-cache.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False, and the tool exits 0 in default mode. The opt-in env
AUDITOOOR_RESET_CONSERVATION_STRICT (or --strict) only raises the exit code when
a fired row exists.

Excludes machine-generated (.pb.go/.pulsar.go + "DO NOT EDIT"), test, sim and
vendored code via the shared exclusion libs. Silent on other trees.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/reset_conservation_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar - tests/verify)
  --file <f>         scan a single .sol/.go file, print rows as JSON
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

HYP_SCHEMA = "auditooor.reset_conservation_hypotheses.v1"
_SIDE_NAME = "reset_conservation_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_RESET_CONSERVATION_STRICT"
_CAPABILITY = "GEN_A3"

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
        spec = importlib.util.spec_from_file_location("_dc_screen_rc", tool)
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
              "node", "testdata", "audits"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|"
    r"fixtures|simulation|simapp|testdata)(/|$)")


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
    r"|modifier\s+([A-Za-z_]\w*)"                # Solidity modifier m
    r"|(constructor|receive|fallback)\b"         # Solidity constructor/receive/fallback
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"   # Go func (recv) Foo / func Foo
    r")")


def _fn_name(m):
    return m.group(1) or m.group(2) or m.group(3) or m.group(4)


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
# Solidity reentrancy-flag arm
# ============================================================================
# a guard flag by name (last identifier segment of the LHS)
_GUARD_STEM_RE = re.compile(
    r"(?i)^_*(status|lock(?:ed)?|unlocked|entered|notentered|reentran\w*|mutex|"
    r"guard)$")
# engaged / default value tokens (lower-cased RHS)
_ENGAGED_VALS = {"true", "2", "_entered", "entered", "_true", "locked",
                 "_locked"}
_DEFAULT_VALS = {"false", "0", "1", "_not_entered", "not_entered", "_false",
                 "unlocked", "_unlocked"}
# LHS = RHS-token ; assignment (avoid ==, <=, >=, !=)
_ASSIGN_RE = re.compile(
    r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*(?<![=!<>+\-*/%&|^])=(?!=)\s*"
    r"([A-Za-z0-9_.]+)\s*;")
_DELETE_RE = re.compile(r"\bdelete\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;")
_RETURN_STMT_RE = re.compile(r"\breturn\b")
# transient keyword declaration:  <type> transient <name> ;
_TRANSIENT_DECL_RE = re.compile(
    r"\b[A-Za-z_]\w*(?:\s*\[[^\]]*\])?\s+transient\s+([A-Za-z_]\w*)")


def _guard_assignments(body: str):
    """Return list of (offset, base_name, full_lhs, kind) for guard-named
    assignments in `body`; kind in {'engaged','default'}; None for unknown RHS
    or non-guard names."""
    out = []
    for m in _ASSIGN_RE.finditer(body):
        lhs, rhs = m.group(1), m.group(2)
        base = lhs.split(".")[-1]
        if not _GUARD_STEM_RE.match(base):
            continue
        # skip constant/immutable declarations (ALL-CAPS convention, e.g.
        # `uint256 constant _ENTERED = 2;`) - those are definitions, not sets.
        stripped = base.lstrip("_")
        if stripped and stripped.isupper():
            continue
        rl = rhs.lower()
        if rl in _ENGAGED_VALS:
            out.append((m.start(), base, lhs, "engaged"))
        elif rl in _DEFAULT_VALS:
            out.append((m.start(), base, lhs, "default"))
    for m in _DELETE_RE.finditer(body):
        lhs = m.group(1)
        base = lhs.split(".")[-1]
        if _GUARD_STEM_RE.match(base):
            out.append((m.start(), base, lhs, "default"))
    return out


def _scan_sol_reentrancy_fnscope(rel, name, decl_idx, body, transient_names,
                                 rows):
    """Function-scope S_GUARD_EARLY_RETURN: engaged set + later default reset in
    the SAME fn, with a `return` between them."""
    assigns = _guard_assignments(body)
    by_base = {}
    for off, base, lhs, kind in assigns:
        by_base.setdefault(base, []).append((off, kind))
    for base, items in by_base.items():
        engaged = [o for o, k in items if k == "engaged"]
        defaults = [o for o, k in items if k == "default"]
        if not engaged or not defaults:
            continue
        s = max(engaged)
        after = [d for d in defaults if d > s]
        if not after:
            continue  # no reset after the last set -> handled at file scope
        r = min(after)
        between = body[s:r]
        if _RETURN_STMT_RE.search(between):
            store_kind = ("transient" if base in transient_names
                          else "reentrancy-flag")
            rows.append(_mk_row(
                rel, name, _line_of_offset(body, s) + decl_idx, "solidity",
                "S_GUARD_EARLY_RETURN", base, store_kind,
                "reset-not-dominating-exit", _excerpt(body, s),
                f"guard flag `{base}` is set engaged then a `return` occurs "
                f"before the default reset in `{name}` - the early-return edge "
                f"leaves `{base}` engaged into the next call/tx scope "
                f"(reset must dominate every exit edge)."))


def _scan_sol_reentrancy_filescope(rel, text, transient_names, fn_of_offset,
                                   rows):
    """File-scope S_GUARD_RESET_MISSING: a guard set engaged somewhere but never
    reset to default (or deleted) anywhere in the file."""
    assigns = _guard_assignments(text)
    by_base = {}
    for off, base, lhs, kind in assigns:
        by_base.setdefault(base, []).append((off, kind))
    for base, items in by_base.items():
        engaged = [o for o, k in items if k == "engaged"]
        defaults = [o for o, k in items if k == "default"]
        if not engaged or defaults:
            continue  # either not set, or a reset exists -> not this defect
        s = min(engaged)
        fn = fn_of_offset(s)
        store_kind = ("transient" if base in transient_names
                      else "reentrancy-flag")
        rows.append(_mk_row(
            rel, fn, _line_of_offset(text, s), "solidity",
            "S_GUARD_RESET_MISSING", base, store_kind,
            "reset-not-dominating-exit", _excerpt(text, s),
            f"guard flag `{base}` is set to its engaged value but is NEVER reset "
            f"to default (no `{base} = false/0/_NOT_ENTERED`, no `delete`) "
            f"anywhere in the file - the guard stays permanently engaged, "
            f"bricking every guarded entry point after the first call."))


# ============================================================================
# Solidity transient-tier arm (tstore / sstore)
# ============================================================================
def _matching_paren(s: str, open_idx: int) -> int:
    depth = 0
    for k in range(open_idx, len(s)):
        if s[k] == "(":
            depth += 1
        elif s[k] == ")":
            depth -= 1
            if depth == 0:
                return k + 1
    return len(s)


def _split_top_commas(param_str: str):
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


_STORE_CALL_RE = re.compile(r"\b(tstore|sstore)\s*\(")


def _norm_slot(s: str) -> str:
    return re.sub(r"\s+", "", s)


def _is_zero(v: str) -> bool:
    v = v.strip()
    return v in ("0", "0x0", "0x00", "false") or bool(
        re.fullmatch(r"0x0+", v))


def _scan_sol_transient(rel, text, fn_of_offset, rows):
    """S_TIER_MISMATCH (same slot in tstore & sstore) and S_TSTORE_RESET_MISSING
    (tstore engaged with no tstore(...,0) reset for that slot)."""
    tstore_set = {}     # slot -> [offsets] with nonzero value
    tstore_reset = set()  # slots with a zero-value tstore
    sstore_slots = {}   # slot -> [offsets]
    for m in _STORE_CALL_RE.finditer(text):
        op = m.group(1)
        args = _split_top_commas(text[m.end():_matching_paren(text, m.end() - 1) - 1])
        if len(args) < 2:
            continue
        slot = _norm_slot(args[0])
        val = args[1]
        if op == "tstore":
            if _is_zero(val):
                tstore_reset.add(slot)
            else:
                tstore_set.setdefault(slot, []).append(m.start())
        else:  # sstore
            sstore_slots.setdefault(slot, []).append(m.start())

    # S_TIER_MISMATCH: a slot written by BOTH tstore and sstore
    for slot in set(tstore_set) | tstore_reset:
        if slot in sstore_slots:
            off = (tstore_set.get(slot, []) + sstore_slots[slot])[0]
            fn = fn_of_offset(off)
            rows.append(_mk_row(
                rel, fn, _line_of_offset(text, off), "solidity",
                "S_TIER_MISMATCH", slot[:48], "transient",
                "tier-mismatch-set-vs-reset", _excerpt(text, off),
                f"slot `{slot[:48]}` is written by BOTH tstore (transient) and "
                f"sstore (persistent) - a transient set reset by a persistent "
                f"store (or the reverse) mismatches storage tiers and poisons "
                f"cross-tx state (TSTORE-poison / delete-mis-emits-sstore)."))

    # S_TSTORE_RESET_MISSING: transient set with no transient reset for that slot
    for slot, offs in tstore_set.items():
        if slot in tstore_reset or slot in sstore_slots:
            continue  # a reset exists (transient) or already flagged as mismatch
        off = offs[0]
        fn = fn_of_offset(off)
        rows.append(_mk_row(
            rel, fn, _line_of_offset(text, off), "solidity",
            "S_TSTORE_RESET_MISSING", slot[:48], "transient",
            "reset-not-dominating-exit", _excerpt(text, off),
            f"transient slot `{slot[:48]}` is set via tstore to a nonzero value "
            f"but is never reset (`tstore({slot[:24]}, 0)`) in the file - the "
            f"transient value survives for the rest of the tx and is trusted by "
            f"the next call scope within the same transaction."))


# ============================================================================
# Go tx-scoped cache arm (secondary)
# ============================================================================
_GO_CACHE_STEM_RE = re.compile(
    r"(?i)(cache|scoped?|pending|current|active|txctx|txcache|guard|locked?|"
    r"session|inflight)$")
_GO_ASSIGN_RE = re.compile(
    r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*(?<![=!<>:+\-*/%&|^])=(?!=)\s*([^\n;]+)")
_GO_DEFER_RE = re.compile(r"\bdefer\b")


def _scan_go_fn(rel, name, decl_idx, body, rows):
    # a defered reset dominates all exits -> not this defect.
    if _GO_DEFER_RE.search(body):
        return
    by_base = {}
    for m in _GO_ASSIGN_RE.finditer(body):
        lhs, rhs = m.group(1), m.group(2).strip()
        base = lhs.split(".")[-1]
        if not _GO_CACHE_STEM_RE.search(base):
            continue
        default = rhs.startswith("nil") or rhs in ("0", "false", '""')
        by_base.setdefault(lhs, []).append((m.start(), "default" if default
                                             else "set"))
    for lhs, items in by_base.items():
        sets = [o for o, k in items if k == "set"]
        defaults = [o for o, k in items if k == "default"]
        if not sets or not defaults:
            continue
        s = max(sets)
        after = [d for d in defaults if d > s]
        if not after:
            continue
        r = min(after)
        if _RETURN_STMT_RE.search(body[s:r]):
            rows.append(_mk_row(
                rel, name, _line_of_offset(body, s) + decl_idx, "go",
                "G_CACHE_EARLY_RETURN", lhs.split(".")[-1], "tx-cache",
                "reset-not-dominating-exit", _excerpt(body, s),
                f"scoped cache field `{lhs}` is set then reset later in `{name}`, "
                f"but a `return` sits between the set and the reset with no "
                f"`defer`ed reset - an error/early-return edge leaks the scoped "
                f"value into the next scope."))


# ============================================================================
# row + summary
# ============================================================================
def _mk_row(rel, fn, line, lang, kind, store_var, store_kind, defect, excerpt,
            why):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, fn, kind, store_var, line),
        "file": rel,
        "line": line,
        "function": fn,
        "context": fn,
        "lang": lang,
        "pattern_id": kind,
        "store_var": store_var,
        "store_kind": store_kind,
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
    lang = "go" if rel.lower().endswith(".go") else "solidity"
    lines = text.split("\n")
    rows = []

    if lang == "go":
        for name, decl_idx, sig, body_lines in _functions(lines):
            _scan_go_fn(rel, name, decl_idx, _body_after_sig(body_lines), rows)
        return rows

    # ---- Solidity ----
    transient_names = set(_TRANSIENT_DECL_RE.findall(text))

    # map an absolute offset -> enclosing function name (for file-scope rows)
    fn_spans = []  # (start_off, end_off, name)
    line_starts = []
    pos = 0
    for ln in lines:
        line_starts.append(pos)
        pos += len(ln) + 1
    for name, decl_idx, sig, body_lines in _functions(lines):
        if not body_lines:
            continue
        start_idx = body_lines[0][0]
        end_idx = body_lines[-1][0]
        so = line_starts[start_idx] if start_idx < len(line_starts) else 0
        eo = (line_starts[end_idx] + len(lines[end_idx])
              if end_idx < len(line_starts) else len(text))
        fn_spans.append((so, eo, name))

    def fn_of_offset(off):
        for so, eo, nm in fn_spans:
            if so <= off <= eo:
                return nm
        return "<file>"

    # per-function early-return bypass
    for name, decl_idx, sig, body_lines in _functions(lines):
        _scan_sol_reentrancy_fnscope(
            rel, name, decl_idx, _body_after_sig(body_lines),
            transient_names, rows)

    # file-scope reset-missing + transient-tier
    _scan_sol_reentrancy_filescope(rel, text, transient_names, fn_of_offset,
                                   rows)
    _scan_sol_transient(rel, text, fn_of_offset, rows)
    return rows


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
        "stores": len(rows),
        "fired": len(fired),
        "by_pattern": _count(rows, "pattern_id"),
        "by_lang": _count(rows, "lang"),
        "by_store_kind": _count(rows, "store_kind"),
        "by_defect": _count(rows, "defect"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-A3 ephemeral-store reset-conservation + write-tier "
                    "fidelity screen (Solidity + Go, advisory)")
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
