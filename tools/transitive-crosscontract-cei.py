#!/usr/bin/env python3
"""transitive-crosscontract-cei.py  (TCCEI - RANK-5 burndown, HIGH x67).

TRANSITIVE CROSS-CONTRACT CEI / READ-ONLY REENTRANCY screen.
==========================================================================
GENERAL ENFORCEMENT CLASS (an ordering/closure property, not a bug shape)
--------------------------------------------------------------------------
A function F does  READ(S) -> EXTERNAL_CALL c -> {c's transitive callee
closure across delegatecall / hook / cross-contract edges CONTAINS a
WRITE(S)} -> subsequent USE(S) in F, where NO reentrancy lock DOMINATES the
whole window.  The write that invalidates F's cached read of the state var S
happens in a DIFFERENT function / contract, reached TRANSITIVELY through the
external call.  A single-contract `nonReentrant` on F does NOT protect this:
a fresh entry into a sibling / hooked contract is not on F's call stack, so
F's own per-instance lock is never engaged for the re-entered writer.

This is the class behind cross-contract read-only reentrancy (Curve-style),
hook-callback reentrancy, and ERC777 / ERC1155 / ERC721 receiver-hook
reentrancy where the mutation lands in a related-but-distinct module.

NOVELTY vs the existing single-fn CEI detector
--------------------------------------------------------------------------
The single-fn CEI detector fires when the write that F relies on is in F's
OWN body (write-after-interaction inside one function).  TCCEI fires only
when the invalidating WRITE(S) is in a DIFFERENT function (SURVIVOR requires
writer_fn != F), and it is reachable transitively during the window.  The
guard-dominance test therefore spans the WHOLE transitive window
(has_guard_in_closure), not just F's modifier list: a shared / global lock
(or, for a SAME-contract writer, a per-instance nonReentrant on BOTH F and
the writer) suppresses the row; separate per-module locks on a
CROSS-contract writer do NOT.

SURVIVOR predicate (the ordering/closure difference)
--------------------------------------------------------------------------
A (state_var S, function F) SURVIVES iff ALL hold:
  1. READ(S)  : F reads S at a source position BEFORE an external call c.
  2. EXTCALL c: F contains an external / attacker-reachable call window
     (hook / callback / receiver-acceptance / low-level .call / delegatecall
     / resolved cross-contract call).
  3. TRANSITIVE-WRITE-REACHABLE: the reentry closure of c (see below) CONTAINS
     a function writer_fn != F that WRITEs the SAME S.
  4. USE(S)   : F references S again at a position AFTER c (the stale use).
  5. NOT guard-dominated over the window: no lock DOMINATES both F and
     writer_fn across the window (has_guard_in_closure == False).
  6. Entrypoint-reachable: F is public/external or reachable from one.

Reentry closure of c:
  - attacker-controlled window (hook/callback/receiver/low-level .call to an
    unresolved target / delegatecall to unknown): the attacker chooses the
    re-entered entrypoint, so the closure = ALL owned public/external
    functions and their transitive owned callees.
  - resolved cross-contract call to a known owned contract C: closure = C's
    public/external functions + their transitive owned callees.
When the target type of a cross-contract edge cannot be resolved to an owned
contract, the row is still emitted but flagged advisory `needs_source=true`
(the edge is unresolved; a human / deeper engine must confirm reachability).

GUARD DOMINANCE (has_guard_in_closure)
--------------------------------------------------------------------------
Dominated (row SUPPRESSED) iff EITHER:
  (a) writer_fn is in the SAME contract as F AND both F and writer_fn carry a
      reentrancy guard (a per-instance nonReentrant blocks cross-function
      same-contract re-entry), OR
  (b) F and writer_fn reference a SHARED / GLOBAL / system / protocol / cross
      reentrancy lock token (genuine cross-module protection).
Otherwise the window is UNGUARDED across the closure -> SURVIVOR.  This is the
guard whose addition flips a survivor to silence (mutation-verification).

ADVISORY-FIRST / NO AUTO-CREDIT (never fail-closed on findings)
--------------------------------------------------------------------------
Every emitted row carries verdict="needs-fuzz" and attack_class=
"transitive-crosscontract-cei".  TCCEI NEVER credits a gate and NEVER
asserts a finding: it enumerates (S, F) survivors for a coverage-guided
campaign / manual review.  A degraded feeder or a parse miss produces FEWER
rows, never a false "clean".  `--fail-closed` only affects the PROCESS exit
code for a VACUOUS SUBSTRATE (no parseable owned Solidity), so a pipeline can
distinguish "honest cited-empty" (real substrate, 0 survivors) from
"substrate_vacuous" (nothing to analyze).

OUTPUT SCHEMA  auditooor.transitive_crosscontract_cei.v1
--------------------------------------------------------------------------
{
  "schema": "auditooor.transitive_crosscontract_cei.v1",
  "workspace": "<abs>", "language": "sol",
  "state_var": "S", "function": "F", "contract": "Ca", "file": "...",
  "line": <int F decl line>,
  "read_line": <int>, "extcall_line": <int>, "use_line": <int>,
  "writer_function": "writer_fn", "writer_contract": "Cb",
  "writer_file": "...", "writer_line": <int>,
  "cross_contract": true|false,
  "reentry_path": "F reads S @L -> extcall @L -> Cb.writer_fn writes S @L -> F uses S @L",
  "source_refs": ["file:line", ...],
  "window_evidence": "<snippet>",
  "needs_source": true|false,           # advisory: unresolved cross edge
  "attack_class": "transitive-crosscontract-cei",
  "sub_class": "cross-contract-write-reentrancy|readonly-cross-contract-reentrancy|hook-callback-reentrancy",
  "source": "TCCEI", "verdict": "needs-fuzz"
}

CLI
--------------------------------------------------------------------------
  python3 tools/transitive-crosscontract-cei.py --workspace <ws> \
      [--src-root <dir>] [--emit] [--json] [--fail-closed]

  --src-root  scan root override (defaults to <workspace>); paths in output
              are relative to the scan root.
  --emit      write the .jsonl sidecar (default: dry, summary only).
  --json      print a machine summary object to stdout.
  --fail-closed  exit rc=2 when the substrate is VACUOUS (no owned Solidity
              parsed) so a pipeline never mistakes vacuity for a clean 0.

Importable: produce_survivors(ws, src_root) / evaluate(ws, ...) for tests.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_SIDECAR_NAME = "transitive_crosscontract_cei.jsonl"
SCHEMA = "auditooor.transitive_crosscontract_cei.v1"

# ---------------------------------------------------------------------------
# OOS helper (same fallback chain as the rest of tools/).
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + rel.replace("\\", "/")).lower()
            for marker in (
                "/test/", "/tests/", "_test.", ".t.sol", "/vendor/",
                "/node_modules/", "/forge-std/", "/mock", "/script/",
                "/scripts/", "/artifacts/",
            ):
                if marker in n:
                    return True
            return False


_EXT_TO_LANG: dict[str, str] = {".sol": "sol", ".vy": "sol"}

# ===========================================================================
# Lexicons
# ===========================================================================
# External / attacker-reachable call window.  Neutralising this list silences
# every window and therefore every row (load-bearing; the non-vacuity test
# swaps it to a never-match sentinel).
_CALLBACK_RES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\.onFlashLoan\s*\(", re.I), "hook"),
    (re.compile(r"\.onMorpho\w*\s*\(", re.I), "hook"),
    (re.compile(r"\bonERC1155Received\s*\("), "hook"),
    (re.compile(r"\bonERC1155BatchReceived\s*\("), "hook"),
    (re.compile(r"\bonERC721Received\s*\("), "hook"),
    (re.compile(r"\bonERC777\w*\s*\(", re.I), "hook"),
    (re.compile(r"\btokensReceived\s*\("), "hook"),
    (re.compile(r"\btokensToSend\s*\("), "hook"),
    (re.compile(r"\.\s*on[A-Z]\w*\s*\("), "hook"),          # .on<Cap>* dispatch
    (re.compile(r"\.\s*\w+Callback\s*\(", re.I), "hook"),
    (re.compile(r"\.\s*\w+Hook\s*\(", re.I), "hook"),
    (re.compile(r"\.\s*delegatecall\s*\("), "delegatecall"),
    (re.compile(r"\.\s*call\s*\{"), "lowlevel-call"),
    (re.compile(r"\.\s*call\s*\("), "lowlevel-call"),
    (re.compile(r"\bsafeTransfer(?:From)?\s*\("), "token-transfer"),
    (re.compile(r"\b_safeTransfer(?:From)?\s*\("), "token-transfer"),
]

_VALUE_ROOTS_RE = re.compile(
    r"balance|credit|debt|share|amount|asset|vault|escrow|collateral"
    r"|reserve|stake|supply|borrow|lend|deposit|withdraw|liquidity|fund"
    r"|pool|holding|position|reward|total|nav|principal|accrued|owed"
    r"|outstanding|pending|value|price|rate|index|virtualprice|exchange",
    re.IGNORECASE,
)

_TOKEN_STOPWORDS: frozenset[str] = frozenset({
    "owner", "admin", "paused", "initialized", "version", "nonce", "operator",
    "controller", "manager", "config", "flag", "lock", "locked",
    "status", "role", "guardian", "pauser", "timestamp", "deadline",
    "id", "true", "false", "this", "msg", "self", "memory", "storage",
    "calldata", "uint", "int", "bool", "address", "bytes", "string",
    "return", "require", "assert", "emit", "new", "if", "for", "while",
    "mapping", "struct", "event", "modifier", "function",
})

_GUARD_RES: list[re.Pattern] = [
    re.compile(r"\bnonReentrant\b"),
    re.compile(r"\bReentrancyGuard\b"),
    re.compile(r"\b_status\s*=\s*_ENTERED\b"),
    re.compile(r"\b_locked\s*=\s*true\b"),
    re.compile(r"\b_entered\s*=\s*true\b"),
    re.compile(r"\bREENTRANCY_LOCK\b"),
    re.compile(r"\bnoReentry\b", re.I),
    re.compile(r"\block\s*\(\s*\)"),
]

# A shared / global lock spanning modules is genuinely sound protection.
_GLOBAL_LOCK_RE = re.compile(
    r"\b\w*(?:global|shared|system|protocol|cross)\w*"
    r"(?:reentran|lock|guard|mutex|entered)\w*\b",
    re.IGNORECASE,
)

_WRITE_RE = re.compile(
    r"(?<![.\w])([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>])[-+*/|&^%]?=(?!=)"
)
_LOCAL_DECL_RE = re.compile(
    r"\b(?:u?int\d*|address|bool|bytes\d*|string|mapping|[A-Z]\w*)\s+"
    r"(?:memory\s+|storage\s+|calldata\s+)?([A-Za-z_]\w*)\s*(?:=|;)"
)
_IDENT_RE = re.compile(r"\b([A-Za-z_]\w*)\b")

_COMMENT_OR_STR_RE = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'",
    re.DOTALL,
)
_CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|library|interface)\s+([A-Za-z_]\w*)\b"
    r"([^{;]*)\{"
)
_FN_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")
_STATE_VAR_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;{}]*?\)|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?(?:\[[^\]]*\])*)\s+"
    r"(?:(?:public|private|internal|constant|immutable|override|transient)\s+)*"
    r"([A-Za-z_]\w*)\s*(?:=|;)"
)
_BASE_RE = re.compile(r"\bis\b(.*)", re.DOTALL)
_VIS_RE = re.compile(r"\b(external|public|internal|private)\b")

# Internal / cross-contract call site: `foo(` (internal) or `bar.foo(` /
# `Type.foo(` (cross). We resolve the callee fn NAME; the receiver token (if
# any) is used to attempt owned-contract resolution.
_CALL_SITE_RE = re.compile(
    r"(?:([A-Za-z_]\w*)\s*\.\s*)?([A-Za-z_]\w*)\s*\("
)


def _is_value_token(tok: str) -> bool:
    if len(tok) <= 2 or tok.lower() in _TOKEN_STOPWORDS:
        return False
    return bool(_VALUE_ROOTS_RE.search(tok))


def _strip_comments(text: str) -> str:
    def _blank(m: re.Match) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in m.group(0))
    return _COMMENT_OR_STR_RE.sub(_blank, text)


def _extract_body(source: str, sig_end: int) -> tuple[str, int]:
    """Return (body_text, body_start_char) or ("", -1) for a bodiless decl."""
    i = source.find("{", sig_end)
    if i < 0:
        return "", -1
    semi = source.find(";", sig_end)
    if semi != -1 and semi < i:
        return "", -1
    depth = 0
    for j in range(i, len(source)):
        c = source[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[i + 1:j], i + 1
    return source[i + 1:], i + 1


def _split_contracts(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in _CONTRACT_RE.finditer(text):
        name = m.group(1)
        header = m.group(2) or ""
        bases: set[str] = set()
        bm = _BASE_RE.search(header)
        if bm:
            for tm in re.finditer(r"([A-Za-z_]\w*)", bm.group(1)):
                bases.add(tm.group(1))
        brace = m.end() - 1
        depth = 0
        end = len(text)
        for j in range(brace, len(text)):
            c = text[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
        out.append({
            "name": name,
            "bases": bases,
            "body": text[brace + 1:end],
            "body_offset": brace + 1,
        })
    return out


def _state_vars(contract: dict[str, Any]) -> set[str]:
    body = contract["body"]
    names: set[str] = set()
    depth = 0
    stmt_start = 0
    for i, c in enumerate(body):
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            stmt_start = i + 1
        elif c == ";" and depth == 0:
            m = _STATE_VAR_RE.match(body[stmt_start:i + 1])
            if m:
                names.add(m.group(1))
            stmt_start = i + 1
    return names


def _functions_of(text: str, contract: dict[str, Any]) -> list[dict[str, Any]]:
    body = contract["body"]
    base_off = contract["body_offset"]
    fns: list[dict[str, Any]] = []
    for m in _FN_RE.finditer(body):
        name = m.group(1)
        sig_end = m.end()
        mod_end = body.find("{", sig_end)
        semi = body.find(";", sig_end)
        if mod_end < 0 or (semi != -1 and semi < mod_end):
            continue
        mod_prefix = body[sig_end:mod_end]
        fbody, body_start = _extract_body(body, sig_end)
        if body_start < 0:
            continue
        fn_abs_start = base_off + m.start()
        vis_m = _VIS_RE.search(mod_prefix)
        vis = vis_m.group(1) if vis_m else "public"  # solidity default is public
        fns.append({
            "name": name,
            "line": text[:fn_abs_start].count("\n") + 1,
            "mod_prefix": mod_prefix,
            "body": fbody,
            "body_abs_offset": base_off + body_start,
            "visibility": vis,
        })
    return fns


def _line_of(text: str, abs_pos: int) -> int:
    return text[:abs_pos].count("\n") + 1


def _writes(body: str) -> set[str]:
    return {m.group(1) for m in _WRITE_RE.finditer(body)}


def _local_decls(body: str) -> set[str]:
    return {m.group(1) for m in _LOCAL_DECL_RE.finditer(body)}


def _fn_is_guarded(fn: dict[str, Any]) -> bool:
    combined = fn["mod_prefix"] + fn["body"][:400]
    return any(rx.search(combined) for rx in _GUARD_RES)


# One-shot initializers / constructors cannot be re-entered as a reentrancy
# WRITER (a fresh call reverts on the initializer flag), so they are not a
# genuine transitive re-entry writer. Excluding them removes the dominant
# false-positive class (config setters that write immutable-ish state once).
_INIT_NAME_RE = re.compile(r"^(?:initialize\w*|__?init\w*|constructor)$", re.I)
_INIT_MOD_RE = re.compile(r"\b(?:initializer|onlyInitializing|reinitializer)\b")


def _is_oneshot_initializer(fn: dict[str, Any]) -> bool:
    if _INIT_NAME_RE.match(fn["name"]):
        return True
    return bool(_INIT_MOD_RE.search(fn["mod_prefix"]))


def _global_lock_tokens(fn: dict[str, Any]) -> set[str]:
    combined = fn["mod_prefix"] + fn["body"]
    return {m.group(0).lower() for m in _GLOBAL_LOCK_RE.finditer(combined)}


def _callsites(body: str) -> list[tuple[str | None, str]]:
    """List of (receiver_or_None, callee_name) call sites in a body."""
    return [(m.group(1), m.group(2)) for m in _CALL_SITE_RE.finditer(body)]


# ---------------------------------------------------------------------------
# Workspace scan.
# ---------------------------------------------------------------------------
def _scan(root: Path) -> list[dict[str, Any]]:
    modules: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or _EXT_TO_LANG.get(path.suffix.lower()) is None:
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)
        if is_oos(rel):
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text = _strip_comments(raw)
        contracts = _split_contracts(text)
        for c in contracts:
            c["fns"] = _functions_of(text, c)
            c["state_vars"] = _state_vars(c)
            c["file"] = rel
            c["text"] = text
        modules.append({"file": rel, "contracts": contracts})
    return modules


def _first_window(fn: dict[str, Any]) -> tuple[int, str, str] | None:
    """Return (pos_in_body, kind, snippet) of the earliest external window."""
    best: tuple[int, str, str] | None = None
    for rx, kind in _CALLBACK_RES:
        m = rx.search(fn["body"])
        if m and (best is None or m.start() < best[0]):
            s = max(0, m.start() - 8)
            snip = fn["body"][s:m.end() + 24].strip().replace("\n", " ")[:80]
            best = (m.start(), kind, snip)
    return best


def _sub_class(kind: str, cross: bool, writer_writes_state: bool) -> str:
    if kind in ("hook", "delegatecall"):
        return "hook-callback-reentrancy"
    if cross and writer_writes_state:
        return "cross-contract-write-reentrancy"
    return "readonly-cross-contract-reentrancy"


# ===========================================================================
# CORE: produce survivors.
# ===========================================================================
def produce_survivors(
    ws: Path | str, src_root: Path | str | None = None
) -> dict[str, Any]:
    """Return {survivors, counts, substrate_vacuous, root}."""
    ws = Path(ws).resolve()
    root = Path(src_root).resolve() if src_root else ws
    modules = _scan(root)

    contracts: list[dict[str, Any]] = []
    for mod in modules:
        contracts.extend(mod["contracts"])

    # owned contract-name set, and a name->contract index (first wins).
    owned_names = {c["name"] for c in contracts}
    by_name: dict[str, dict[str, Any]] = {}
    for c in contracts:
        by_name.setdefault(c["name"], c)

    # fn registry keyed by contract-id -> {fnname: fn}, and global fnname set.
    def cid(c: dict[str, Any]) -> str:
        return f"{c['file']}::{c['name']}"

    fn_index: dict[str, dict[str, dict[str, Any]]] = {}
    contract_of_fn: dict[str, dict[str, Any]] = {}
    for c in contracts:
        fn_index[cid(c)] = {}
        for fn in c["fns"]:
            fn_index[cid(c)][fn["name"]] = fn

    # inherited state vars: a contract's effective state set includes bases
    # resolved by name over owned contracts (best-effort).
    def effective_state(c: dict[str, Any]) -> set[str]:
        seen: set[str] = set()
        stack = [c["name"]]
        acc: set[str] = set()
        while stack:
            nm = stack.pop()
            if nm in seen:
                continue
            seen.add(nm)
            oc = by_name.get(nm)
            if not oc:
                continue
            acc |= oc.get("state_vars", set())
            stack.extend(oc.get("bases", set()))
        return acc

    # transitive owned callee closure of a function (internal + resolvable
    # cross-contract calls) up to a bounded depth.
    def owned_callee_closure(start: dict[str, Any], start_c: dict[str, Any],
                             max_depth: int = 6) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        out: list[tuple[dict, dict]] = []
        seen: set[tuple[str, str]] = set()
        stack = [(start_c, start, 0)]
        while stack:
            c, fn, d = stack.pop()
            key = (cid(c), fn["name"])
            if key in seen:
                continue
            seen.add(key)
            out.append((c, fn))
            if d >= max_depth:
                continue
            for recv, callee in _callsites(fn["body"]):
                targets: list[tuple[dict, dict]] = []
                if recv is None:
                    # internal call in same contract (or inherited base)
                    nx = fn_index.get(cid(c), {}).get(callee)
                    if nx:
                        targets.append((c, nx))
                    else:
                        for bn in c.get("bases", set()):
                            bc = by_name.get(bn)
                            if bc and callee in fn_index.get(cid(bc), {}):
                                targets.append((bc, fn_index[cid(bc)][callee]))
                else:
                    # cross-contract: try to resolve receiver TYPE by name.
                    tc = by_name.get(recv)  # e.g. Type.method (library)
                    if tc and callee in fn_index.get(cid(tc), {}):
                        targets.append((tc, fn_index[cid(tc)][callee]))
                for tcx, tfn in targets:
                    if (cid(tcx), tfn["name"]) not in seen:
                        stack.append((tcx, tfn, d + 1))
        return out

    # all owned entrypoints (attacker-reachable re-entry set).
    entrypoints: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for c in contracts:
        for fn in c["fns"]:
            if fn["visibility"] in ("public", "external"):
                entrypoints.append((c, fn))

    # precompute: reachable-from-entrypoint fn set (for entrypoint filter).
    reachable_fns: set[tuple[str, str]] = set()
    for c, fn in entrypoints:
        for rc, rfn in owned_callee_closure(fn, c):
            reachable_fns.add((cid(rc), rfn["name"]))

    survivors: list[dict[str, Any]] = []
    seen_rows: set[tuple] = set()
    dominated_count = 0

    for c in contracts:
        state_c = effective_state(c)
        for fn in c["fns"]:
            # 6. entrypoint-reachable filter.
            if (cid(c), fn["name"]) not in reachable_fns and \
               fn["visibility"] not in ("public", "external"):
                continue
            win = _first_window(fn)
            if win is None:
                continue
            win_pos, kind, snip = win
            body = fn["body"]
            base = fn["body_abs_offset"]
            extcall_line = _line_of(c["text"], base + win_pos)

            # candidate state vars READ before the window and USED after it.
            locals_ = _local_decls(body)
            pre = body[:win_pos]
            post = body[win_pos:]
            pre_writes = _writes(pre)
            pre_refs = {m.group(1) for m in _IDENT_RE.finditer(pre)}
            post_refs = {m.group(1) for m in _IDENT_RE.finditer(post)}
            # READ(S): referenced (not solely written) before window, is state,
            # value-class, not a local.
            cand: set[str] = set()
            for t in pre_refs & state_c:
                if t in locals_ or not _is_value_token(t):
                    continue
                cand.add(t)
            # USE(S): must also be referenced AFTER the window.
            cand = {t for t in cand if t in post_refs}
            if not cand:
                continue

            read_line = extcall_line  # refine per token below

            # reentry closure of the window.
            if kind in ("hook", "delegatecall", "lowlevel-call",
                        "token-transfer"):
                # attacker-controlled: all owned entrypoints + their closures.
                closure = []
                for ec, efn in entrypoints:
                    closure.extend(owned_callee_closure(efn, ec))
                edge_resolved = False  # attacker target is external/unknown
            else:
                closure = list(owned_callee_closure(fn, c))
                edge_resolved = True

            # find a writer_fn != F in the closure that WRITEs a candidate S.
            for tok in sorted(cand):
                writer: tuple[dict[str, Any], dict[str, Any]] | None = None
                for wc, wfn in closure:
                    if wc is c and wfn["name"] == fn["name"]:
                        continue
                    # one-shot initializers cannot be re-entered as a writer.
                    if _is_oneshot_initializer(wfn):
                        continue
                    # writer must have tok in its declared/effective state OR
                    # tok is state of its own contract; and it WRITEs tok.
                    if tok not in effective_state(wc):
                        continue
                    if tok not in _writes(wfn["body"]):
                        continue
                    if wfn["name"] == fn["name"] and wc is c:
                        continue
                    writer = (wc, wfn)
                    break
                if writer is None:
                    continue
                wc, wfn = writer
                cross = not (wc is c)

                # 5. guard dominance over the window.
                dominated = False
                if not cross:
                    if _fn_is_guarded(fn) and _fn_is_guarded(wfn):
                        dominated = True
                shared = _global_lock_tokens(fn) & _global_lock_tokens(wfn)
                if shared:
                    dominated = True
                if dominated:
                    dominated_count += 1
                    continue

                # refine read/use lines for tok.
                rl = _line_of(c["text"], base + (pre.find(tok)
                              if pre.find(tok) >= 0 else 0))
                ul_off = post.find(tok)
                use_line = _line_of(c["text"], base + win_pos + max(ul_off, 0))
                wl = wfn["line"]  # writer declaration line

                needs_source = (not edge_resolved) or (cross)
                # cross via attacker hook to a *different* owned contract is
                # exactly the resolved-enough case; needs_source true only when
                # the reentry hop could not be tied to an owned contract.
                if edge_resolved and cross:
                    needs_source = False
                writer_writes_state = True
                sub = _sub_class(kind, cross, writer_writes_state)

                path = (
                    f"{c['name']}.{fn['name']} reads {tok} @{rl} -> "
                    f"{kind} window @{extcall_line} -> "
                    f"{wc['name']}.{wfn['name']} writes {tok} @{wl} -> "
                    f"{c['name']}.{fn['name']} uses {tok} @{use_line}"
                )
                src_refs = [
                    f"{c['file']}:{rl}",
                    f"{c['file']}:{extcall_line}",
                    f"{wc['file']}:{wl}",
                    f"{c['file']}:{use_line}",
                ]
                key = (c["file"], c["name"], fn["name"], tok,
                       wc["file"], wc["name"], wfn["name"])
                if key in seen_rows:
                    continue
                seen_rows.add(key)

                survivors.append({
                    "schema": SCHEMA,
                    "workspace": str(ws),
                    "language": "sol",
                    "state_var": tok,
                    "function": fn["name"],
                    "contract": c["name"],
                    "file": c["file"],
                    "line": fn["line"],
                    "read_line": rl,
                    "extcall_line": extcall_line,
                    "use_line": use_line,
                    "writer_function": wfn["name"],
                    "writer_contract": wc["name"],
                    "writer_file": wc["file"],
                    "writer_line": wl,
                    "cross_contract": cross,
                    "reentry_path": path,
                    "source_refs": src_refs,
                    "window_evidence": snip,
                    "needs_source": needs_source,
                    "attack_class": "transitive-crosscontract-cei",
                    "sub_class": sub,
                    "source": "TCCEI",
                    "verdict": "needs-fuzz",
                })

    substrate_vacuous = sum(len(c["fns"]) for c in contracts) == 0

    counts = {
        "read_extcall_use_windows": _count_windows(contracts, effective_state),
        "transitive_write_reachable": len(
            {(s["file"], s["function"], s["state_var"]) for s in survivors}
        ),
        "guard_dominated": dominated_count,
        "survivors": len(survivors),
    }
    return {
        "survivors": survivors,
        "counts": counts,
        "substrate_vacuous": substrate_vacuous,
        "root": str(root),
        "modules": len(modules),
        "contracts": len(contracts),
    }


# The window / dominated counts are diagnostic; compute lightly to avoid a
# second full pass duplicating the core. They are best-effort integers.
_DOMINATED_COUNTER = {"n": 0}


def _count_dominated() -> int:
    return _DOMINATED_COUNTER["n"]


def _count_windows(contracts: list[dict[str, Any]], eff) -> int:
    n = 0
    for c in contracts:
        state_c = eff(c)
        for fn in c["fns"]:
            win = _first_window(fn)
            if win is None:
                continue
            win_pos = win[0]
            body = fn["body"]
            locals_ = _local_decls(body)
            pre = body[:win_pos]
            post = body[win_pos:]
            pre_refs = {m.group(1) for m in _IDENT_RE.finditer(pre)}
            post_refs = {m.group(1) for m in _IDENT_RE.finditer(post)}
            for t in pre_refs & state_c:
                if t in locals_ or not _is_value_token(t):
                    continue
                if t in post_refs:
                    n += 1
    return n


# ---------------------------------------------------------------------------
# Emit + evaluate.
# ---------------------------------------------------------------------------
def run(ws: Path | str, src_root: Path | str | None = None,
        out_path: Path | str | None = None,
        emit: bool = True) -> dict[str, Any]:
    ws = Path(ws).resolve()
    res = produce_survivors(ws, src_root)
    if emit:
        out = (Path(out_path) if out_path is not None
               else ws / ".auditooor" / _SIDECAR_NAME)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            for h in res["survivors"]:
                fh.write(json.dumps(h) + "\n")
            # Capability-vacuity-telltale: the TCCEI screen RAN over a real (non-
            # vacuous) contract substrate and produced 0 survivors. PERSIST an
            # explicit cited-empty examined-record so the reasoner-firing gate scores
            # this FIRED_CLEAN (ran, examined, recorded 0) not silently VACUOUS.
            if not res["survivors"] and not res["substrate_vacuous"]:
                fh.write(json.dumps({
                    "schema": "auditooor.transitive_crosscontract_cei.examined_record.v1",
                    "note": ("cited-empty: transitive cross-contract CEI screen ran "
                             "over the contract substrate, 0 survivors"),
                    "survivors": [],
                    "report": {
                        "reasoner": "transitive-crosscontract-cei",
                        "totals": {"examined": int(
                            res.get("counts", {}).get("candidate_state_reads", 0)
                            or res.get("counts", {}).get("scanned", 0) or 0)},
                        "counts": res.get("counts", {}),
                    },
                }) + "\n")
        res["sidecar"] = str(out)
    return res


def evaluate(ws: Path | str, src_root: Path | str | None = None,
             emit: bool = False) -> dict[str, Any]:
    res = run(ws, src_root, emit=emit)
    status = ("substrate_vacuous" if res["substrate_vacuous"]
              else ("cited-empty" if res["counts"]["survivors"] == 0
                    else "survivors"))
    return {
        "transitive_crosscontract_cei": {
            "verdict": "needs-fuzz",
            "status": status,
            "counts": res["counts"],
            "substrate_vacuous": res["substrate_vacuous"],
            "root": res["root"],
            "survivors": res["survivors"],
        }
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------
def _main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="TCCEI: transitive cross-contract CEI / read-only "
                    "reentrancy survivor screen (needs-fuzz, no auto-credit)."
    )
    p.add_argument("--workspace", required=True, help="Workspace root")
    p.add_argument("--src-root", default=None,
                   help="Scan-root override (paths relative to this)")
    p.add_argument("--emit", action="store_true", help="Write .jsonl sidecar")
    p.add_argument("--json", action="store_true", help="Print summary JSON")
    p.add_argument("--fail-closed", action="store_true",
                   help="rc=2 when substrate is vacuous")
    args = p.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 1

    res = run(ws, args.src_root, emit=args.emit)
    counts = res["counts"]
    status = ("substrate_vacuous" if res["substrate_vacuous"]
              else ("cited-empty" if counts["survivors"] == 0 else "survivors"))

    if args.json:
        print(json.dumps({
            "schema": SCHEMA,
            "status": status,
            "counts": counts,
            "substrate_vacuous": res["substrate_vacuous"],
            "root": res["root"],
            "modules": res["modules"],
            "contracts": res["contracts"],
            "sidecar": res.get("sidecar"),
        }, indent=2))
    else:
        print(f"TCCEI [{status}] root={res['root']}")
        print(f"  modules={res['modules']} contracts={res['contracts']}")
        print(f"  |read-extcall-use windows|   = "
              f"{counts['read_extcall_use_windows']}")
        print(f"  |transitive-write-reachable| = "
              f"{counts['transitive_write_reachable']}")
        print(f"  |survivors|                  = {counts['survivors']}")
        for s in res["survivors"][:25]:
            xc = "CROSS" if s["cross_contract"] else "same"
            ns = " needs_source" if s["needs_source"] else ""
            print(f"  [{xc}] {s['contract']}.{s['function']} S={s['state_var']}"
                  f" <- {s['writer_contract']}.{s['writer_function']}"
                  f" ({s['sub_class']}){ns}")
        if len(res["survivors"]) > 25:
            print(f"  ... ({len(res['survivors']) - 25} more)")

    if args.fail_closed and res["substrate_vacuous"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(_main())
