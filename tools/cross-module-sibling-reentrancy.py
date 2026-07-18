#!/usr/bin/env python3
"""cross-module-sibling-reentrancy.py  (CMSR - capability A7).

CROSS-MODULE REENTRANCY / CALLBACK-INTO-SIBLING screen.
==========================================================================
GENERAL ENFORCEMENT CLASS (not a bug shape)
--------------------------------------------------------------------------
A7 encodes ONE reusable trust-enforcement invariant, applied via the
north-star method ("a TRUSTED ENFORCEMENT is bypassable or its private
invariant is unsound"):

  DELEGATED-AND-TRUSTED SAFETY PROPERTY (what the code assumes):
    "Reentrancy safety is enforced PER MODULE. Each contract's checks-
     effects-interactions ordering holds within its own body, and/or each
     contract carries its own ReentrancyGuard / lock. Therefore the system
     is reentrancy-safe."

  PRIVATE INVARIANT (what is actually required, and is UNSOUND above):
    "A reentrancy lock must span the WHOLE cross-module composition. When a
     module A hands control to an attacker (an external callback window),
     any RELATED SIBLING module B that touches state COUPLED to A must NOT
     be freely re-enterable while A's coupled state is in flight. A
     per-module lock on A does not protect B - and a fresh entry into a
     DIFFERENT contract B is not on A's call stack, so B's OWN per-module
     lock is not engaged either. The only sound protection is a lock that
     SPANS both modules (a shared/global lock) or that B is not re-enterable
     during the window at all."

  ATTACK ON THE INVARIANT (the general defect this screen enumerates):
    A (contract Ca) opens an unguarded external callback window and touches
    a value-class state token V. A SIBLING function B in a DIFFERENT,
    RELATED contract Cb reads or writes that SAME coupled token V and is
    itself UNGUARDED by any reentrancy lock. CEI can hold cleanly inside A
    AND inside B; the violation is emergent ACROSS the module boundary -
    the attacker, mid-callback, re-enters B and observes / mutates the
    coupled state that A left in flight.

This is NOT the same as the single-module callback lane
(callback-reentrancy-composition.py / CRC), which pairs a callback window
with a target whose OWN body has a state-write-before-settlement CEI
violation. CMSR fires precisely when NO single module is internally wrong -
each is CEI-clean - but the coupled state is shared across the boundary and
the sibling that touches it lacks a reentrancy guard. See DEDUP below.

ADVISORY-FIRST / NO AUTO-CREDIT (never fail-closed)
--------------------------------------------------------------------------
Every emitted row carries verdict="needs-fuzz" and attack_class=
"cross-module-reentrancy". CMSR NEVER credits a gate, never fails closed,
and never asserts a finding: it enumerates a coupled (window, sibling,
token) triple for a coverage-guided fuzz campaign / manual review to
confirm or refute. A degraded feeder or a parse miss produces FEWER rows,
never a false "clean" verdict that greens anything.

CONSERVATIVE DISCRIMINATOR (keeps false positives near zero)
--------------------------------------------------------------------------
A triple (A_fn in Ca, B_fn in Cb, V) is emitted ONLY when ALL hold:

  1. WINDOW: A_fn opens an external / attacker-reachable callback window
     (named interface callback `.on<Cap>*`/`*Callback`/`*Hook`/flash-loan
     receivers, ERC-1155/721 acceptance hooks, or a low-level
     `.call{...}` / `.delegatecall`). A's own reentrancy-guard status is
     irrelevant - a guard on A never blocks entry into a different Cb.

  2. COUPLED VALUE TOKEN: A_fn WRITES a value-class identifier V (matches the
     value-root lexicon: balance/credit/debt/share/total*/reserve/... and is
     NOT a control token like owner/paused/nonce) and V is NOT a local
     declaration inside A_fn (i.e. it is storage-ish).

  3. DIFFERENT, RELATED CONTRACTS: Cb != Ca, and Ca/Cb are RELATED
     (same file, one inherits the other, a shared base contract, or one
     references the other's type/name). Unrelated contracts that merely
     reuse a common field name do NOT fire (relation predicate is load-
     bearing - it is what makes the token a genuine cross-module coupling).

  4. SIBLING TOUCHES V: B_fn's body references V (read or write).

  5. SIBLING IS UNGUARDED: B_fn carries NO reentrancy guard (no nonReentrant
     modifier, no lock-set, no ReentrancyGuard idiom) AND A/B do not both
     reference a shared/global lock token. A guarded sibling, or a shared/
     global lock spanning both modules, SUPPRESSES the row (this is the
     guard whose removal flips silence -> fire in mutation-verification).

Sub-class: "cross-module-write-reentrancy" when B writes V, else
"cross-module-readonly-reentrancy" (Curve-style stale cross-contract read).

DEDUP vs CRC (callback-reentrancy-composition.py)
--------------------------------------------------------------------------
CRC targets = fns with an intra-body CEI violation (write-before-transfer),
paired to a callback window; its read-only sub-class requires the SAME
workspace view to read a field the window fn writes. CMSR is orthogonal:
its siblings need NO intra-body CEI violation and MUST live in a DIFFERENT,
RELATED contract. Each emitted row carries dedup_hint fields so a consumer
can suppress overlap; CMSR never re-emits a same-contract pair (CRC/SADL
own those).

OUTPUT SCHEMA  (<ws>/.auditooor/cross_module_sibling_reentrancy.jsonl)
--------------------------------------------------------------------------
{
  "workspace": "<abs>", "language": "sol",
  "window_file": "...", "window_contract": "Ca", "window_function": "A_fn",
  "window_line": <int>, "callback_evidence": "<snippet>",
  "sibling_file": "...", "sibling_contract": "Cb", "sibling_function": "B_fn",
  "sibling_line": <int>,
  "coupled_token": "V", "relation": "same-file|inherits|shared-base|type-ref",
  "sibling_touch": "write|read",
  "sub_class": "cross-module-write-reentrancy|cross-module-readonly-reentrancy",
  "note": "<human-readable>",
  "attack_class": "cross-module-reentrancy",
  "source": "CMSR", "verdict": "needs-fuzz",
  "dedup_hint_same_contract": false
}

CLI
--------------------------------------------------------------------------
  python3 tools/cross-module-sibling-reentrancy.py <workspace> [--out PATH]
Advisory summary (enable emit + machine summary):
  produce_hypotheses(ws) / evaluate(ws)   (importable for tests)

Returns rc=0 on success (even with 0 rows), rc=1 on a usage error.
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
                "/test/", "/tests/", "_test.", ".t.sol", "/vendor/", "/lib/",
                "/node_modules/", "/out/", "/build/", "/target/", "/mock",
                "/script/", "/scripts/",
            ):
                if marker in n:
                    return True
            return False


# ===========================================================================
# CORE PREDICATE 1 - callback-window lexicon (attacker-reachable control-yield).
# Neutralising this list silences every window and therefore every row
# (load-bearing; the A7 non-vacuity test flips it to a never-match sentinel).
# ===========================================================================
_SOL_CALLBACK_RES: list[re.Pattern] = [
    re.compile(r"\bIFlashLoan(?:Callback|Receiver)\b", re.I),
    re.compile(r"\bIMorpho(?:Callback|FlashLoan)\b", re.I),
    re.compile(r"\bIUniswap\w*Callee\b", re.I),
    re.compile(r"\.onFlashLoan\s*\(", re.I),
    re.compile(r"\.onMorpho\w*\s*\(", re.I),
    re.compile(r"\.\s*on[A-Z]\w*\s*\("),        # interface .on<Cap>* dispatch
    re.compile(r"\.\s*\w+Callback\s*\(", re.I),
    re.compile(r"\.\s*\w+Hook\s*\(", re.I),
    re.compile(r"\bonERC1155Received\s*\("),
    re.compile(r"\bonERC1155BatchReceived\s*\("),
    re.compile(r"\bonERC721Received\s*\("),
    re.compile(r"\.\s*call\s*\{"),              # low-level value/gas call
    re.compile(r"\.\s*call\s*\("),
    re.compile(r"\.\s*delegatecall\s*\("),
]

# ===========================================================================
# CORE PREDICATE 2 - value-class token lexicon (a genuine coupled-value name).
# ===========================================================================
_VALUE_ROOTS_RE = re.compile(
    r"balance|credit|debt|share|amount|asset|vault|escrow|collateral"
    r"|reserve|stake|supply|borrow|lend|deposit|withdraw|liquidity|fund"
    r"|pool|holding|position|reward|total|nav|principal|accrued|owed"
    r"|outstanding|pending|value",
    re.IGNORECASE,
)

# Control / non-value tokens that must never count as a coupled VALUE token.
_TOKEN_STOPWORDS: frozenset[str] = frozenset({
    "owner", "admin", "paused", "initialized", "version", "nonce", "operator",
    "controller", "manager", "config", "fee", "flag", "lock", "locked",
    "status", "role", "guardian", "pauser", "timestamp", "deadline", "count",
    "index", "idx", "length", "len", "id", "true", "false", "this", "msg",
    "self", "memory", "storage", "calldata", "uint", "int", "bool", "address",
    "bytes", "string", "return", "require", "assert", "emit", "new", "if",
    "for", "while", "mapping", "struct", "event", "modifier", "function",
})


def _is_value_token(tok: str) -> bool:
    if len(tok) <= 2 or tok.lower() in _TOKEN_STOPWORDS:
        return False
    return bool(_VALUE_ROOTS_RE.search(tok))


# ===========================================================================
# CORE PREDICATE 3 - reentrancy-guard lexicon on the SIBLING.
# A sibling carrying any of these is treated as guarded -> row suppressed.
# Removing such a guard on a temp copy flips silence -> fire (mutation-verify).
# ===========================================================================
_SOL_GUARD_RES: list[re.Pattern] = [
    re.compile(r"\bnonReentrant\b"),
    re.compile(r"\bReentrancyGuard\b"),
    re.compile(r"\b_status\s*=\s*_ENTERED\b"),
    re.compile(r"\b_locked\s*=\s*true\b"),
    re.compile(r"\b_entered\s*=\s*true\b"),
    re.compile(r"\bREENTRANCY_LOCK\b"),
    re.compile(r"\bnoReentry\b", re.I),
    re.compile(r"\block\s*\(\s*\)"),
]

# A shared/global lock spanning BOTH modules is genuinely sound protection.
# A generic per-module nonReentrant is NOT shared (per-instance); only a lock
# whose token advertises global/shared/system/protocol/cross scope counts.
_GLOBAL_LOCK_RE = re.compile(
    r"\b\w*(?:global|shared|system|protocol|cross)\w*"
    r"(?:reentran|lock|guard|mutex|entered)\w*\b",
    re.IGNORECASE,
)

# ===========================================================================
# Assignment-target (write) and local-declaration detectors.
# ===========================================================================
_SOL_WRITE_RE = re.compile(
    r"(?<![.\w])([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>])[-+*/|&^%]?=(?!=)"
)
# Local declarations: `uint256 x = ...`, `address y;`, `SomeType z = ...`.
_SOL_LOCAL_DECL_RE = re.compile(
    r"\b(?:u?int\d*|address|bool|bytes\d*|string|mapping|[A-Z]\w*)\s+"
    r"(?:memory\s+|storage\s+|calldata\s+)?([A-Za-z_]\w*)\s*(?:=|;)"
)
_IDENT_RE = re.compile(r"\b([A-Za-z_]\w*)\b")

_EXT_TO_LANG: dict[str, str] = {".sol": "sol", ".vy": "sol"}


# ---------------------------------------------------------------------------
# Balanced-brace body extraction (single logic, mirrors CRC).
# ---------------------------------------------------------------------------
def _extract_body(source: str, sig_end: int) -> str:
    i = source.find("{", sig_end)
    if i < 0:
        return ""
    semi = source.find(";", sig_end)
    if semi != -1 and semi < i:
        return ""  # bodiless interface / abstract declaration
    depth = 0
    for j in range(i, len(source)):
        c = source[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[i + 1: j]
    return source[i + 1:]


def _extract_modifier_prefix(source: str, sig_end: int) -> str:
    i = source.find("{", sig_end)
    if i < 0:
        return source[sig_end: sig_end + 400]
    return source[sig_end:i]


# ---------------------------------------------------------------------------
# Comment stripping (length-preserving: newlines kept so line numbers hold).
# Prevents the words "contract"/"library"/"function" inside comments/strings
# from being parsed as real declarations.
# ---------------------------------------------------------------------------
_COMMENT_OR_STR_RE = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'",
    re.DOTALL,
)


def _strip_comments(text: str) -> str:
    def _blank(m: re.Match) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in m.group(0))
    return _COMMENT_OR_STR_RE.sub(_blank, text)


# ---------------------------------------------------------------------------
# Contract splitter: returns per-contract {name, bases, header, body,
# body_offset (char offset of body start in the file)}.
# ---------------------------------------------------------------------------
_CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|library)\s+([A-Za-z_]\w*)\b"
    r"([^{;]*)\{"
)
_FN_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")

# State-variable declaration at contract scope (depth 0 inside the contract
# body). Captures the declared identifier for `<type> [vis...] name (=|;)`,
# including `mapping(...) public name;` and `uint256[] internal name;`.
_STATE_VAR_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;{}]*?\)|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?(?:\[[^\]]*\])*)\s+"
    r"(?:(?:public|private|internal|constant|immutable|override|transient)\s+)*"
    r"([A-Za-z_]\w*)\s*(?:=|;)"
)
_BASE_RE = re.compile(r"\bis\b(.*)", re.DOTALL)


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
        brace = m.end() - 1  # position of the '{'
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
        body = text[brace + 1: end]
        out.append({
            "name": name,
            "bases": bases,
            "body": body,
            "body_offset": brace + 1,
        })
    return out


# ---------------------------------------------------------------------------
# Per-contract function extraction. Offsets are file-absolute so window/sibling
# line numbers are correct.
# ---------------------------------------------------------------------------
def _state_vars(contract: dict[str, Any]) -> set[str]:
    """Return the set of state-variable identifiers declared at contract scope
    (brace depth 0 within the contract body), ignoring function-local decls."""
    body = contract["body"]
    names: set[str] = set()
    depth = 0
    stmt_start = 0
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            stmt_start = i + 1
        elif c == ";" and depth == 0:
            stmt = body[stmt_start: i + 1]
            m = _STATE_VAR_RE.match(stmt)
            if m:
                names.add(m.group(1))
            stmt_start = i + 1
        i += 1
    return names


def _functions_of(text: str, contract: dict[str, Any]) -> list[dict[str, Any]]:
    body = contract["body"]
    base_off = contract["body_offset"]
    fns: list[dict[str, Any]] = []
    for m in _FN_RE.finditer(body):
        name = m.group(1)
        sig_end = m.end()
        mod_prefix = _extract_modifier_prefix(body, sig_end)
        fbody = _extract_body(body, sig_end)
        if not fbody:
            continue
        fn_abs_start = base_off + m.start()
        line = text[:fn_abs_start].count("\n") + 1
        # body start (file-absolute) for callback line computation
        b_idx = body.find("{", sig_end)
        body_abs_offset = base_off + b_idx + 1 if b_idx >= 0 else fn_abs_start
        fns.append({
            "name": name,
            "line": line,
            "mod_prefix": mod_prefix,
            "body": fbody,
            "body_abs_offset": body_abs_offset,
        })
    return fns


# ---------------------------------------------------------------------------
# Predicate helpers.
# ---------------------------------------------------------------------------
def _find_callback(text: str, fn: dict[str, Any]) -> tuple[bool, int, str]:
    body = fn["body"]
    best_pos: int | None = None
    snippet = ""
    for rx in _SOL_CALLBACK_RES:
        m = rx.search(body)
        if m and (best_pos is None or m.start() < best_pos):
            best_pos = m.start()
            s = max(0, m.start() - 10)
            snippet = body[s: m.end() + 30].strip().replace("\n", " ")[:80]
    if best_pos is None:
        return False, 0, ""
    cb_line = text[: fn["body_abs_offset"] + best_pos].count("\n") + 1
    return True, cb_line, snippet


def _writes(body: str) -> set[str]:
    return {m.group(1) for m in _SOL_WRITE_RE.finditer(body)}


def _local_decls(body: str) -> set[str]:
    return {m.group(1) for m in _SOL_LOCAL_DECL_RE.finditer(body)}


def _refs(body: str) -> set[str]:
    return {m.group(1) for m in _IDENT_RE.finditer(body)}


def _fn_is_guarded(fn: dict[str, Any]) -> bool:
    combined = fn["mod_prefix"] + fn["body"][:400]
    for rx in _SOL_GUARD_RES:
        if rx.search(combined):
            return True
    return False


def _global_lock_tokens(fn: dict[str, Any]) -> set[str]:
    combined = fn["mod_prefix"] + fn["body"]
    return {m.group(0).lower() for m in _GLOBAL_LOCK_RE.finditer(combined)}


def _relation(ca: dict[str, Any], cb: dict[str, Any], same_file: bool) -> str | None:
    """Return the relation label between two contracts, or None if unrelated."""
    if same_file:
        return "same-file"
    na, nb = ca["name"], cb["name"]
    if nb in ca["bases"] or na in cb["bases"]:
        return "inherits"
    if ca["bases"] & cb["bases"]:
        return "shared-base"
    # one references the other's type/name as an identifier in its body
    if re.search(r"\b" + re.escape(na) + r"\b", cb["body"]) or \
       re.search(r"\b" + re.escape(nb) + r"\b", ca["body"]):
        return "type-ref"
    return None


# ---------------------------------------------------------------------------
# Workspace scan -> per-file per-contract function model.
# ---------------------------------------------------------------------------
def _scan_workspace(ws: Path) -> list[dict[str, Any]]:
    """Return list of {file, text, contracts:[{...,'fns':[...]}]} for in-scope
    Solidity files."""
    modules: list[dict[str, Any]] = []
    for path in sorted(ws.rglob("*")):
        if not path.is_file():
            continue
        if _EXT_TO_LANG.get(path.suffix.lower()) is None:
            continue
        try:
            rel = str(path.relative_to(ws))
        except ValueError:
            rel = str(path)
        if is_oos(rel):
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Strip comments/strings (length-preserving) so declaration keywords in
        # prose never parse as real contracts/functions/state-vars.
        text = _strip_comments(raw)
        contracts = _split_contracts(text)
        for c in contracts:
            c["fns"] = _functions_of(text, c)
            c["state_vars"] = _state_vars(c)
        modules.append({"file": rel, "text": text, "contracts": contracts})
    return modules


# ---------------------------------------------------------------------------
# Core: produce cross-module-sibling-reentrancy hypotheses.
# ---------------------------------------------------------------------------
def produce_hypotheses(ws: Path | str) -> list[dict[str, Any]]:
    ws = Path(ws).resolve()
    modules = _scan_workspace(ws)

    # Flatten to a contract list with file/text back-refs.
    contracts: list[dict[str, Any]] = []
    for mod in modules:
        for c in mod["contracts"]:
            c["file"] = mod["file"]
            c["text"] = mod["text"]
            contracts.append(c)

    # WINDOWS: (contract, fn, callback_line, snippet, coupled_tokens[]).
    windows: list[dict[str, Any]] = []
    for c in contracts:
        for fn in c["fns"]:
            has_cb, cb_line, snippet = _find_callback(c["text"], fn)
            if not has_cb:
                continue
            writes = _writes(fn["body"])
            locals_ = _local_decls(fn["body"])
            coupled = {
                t for t in writes
                if t not in locals_ and _is_value_token(t)
            }
            if not coupled:
                continue
            windows.append({
                "contract": c,
                "fn": fn,
                "cb_line": cb_line,
                "snippet": snippet,
                "coupled": coupled,
            })

    if not windows:
        return []

    hypotheses: list[dict[str, Any]] = []
    seen: set[tuple] = set()

    for w in windows:
        ca = w["contract"]
        a_fn = w["fn"]
        for cb in contracts:
            if cb is ca:
                continue
            if cb["name"] == ca["name"] and cb["file"] == ca["file"]:
                continue
            same_file = (cb["file"] == ca["file"])
            rel = _relation(ca, cb, same_file)
            if rel is None:
                continue
            for b_fn in cb["fns"]:
                # same-contract pairs are CRC/SADL territory; here Cb != Ca by
                # construction. Skip if it IS literally the window fn (defensive).
                if cb["name"] == ca["name"] and b_fn["name"] == a_fn["name"]:
                    continue
                b_refs = _refs(b_fn["body"])
                b_writes = _writes(b_fn["body"])
                touched = w["coupled"] & b_refs
                if not touched:
                    continue
                # CORE PREDICATE 2b: the coupled token must be a genuine STATE
                # VARIABLE of one of the two related modules (declared at
                # contract scope), not a coincidental local/param name. This is
                # what makes it a real cross-module storage coupling.
                state_scope = ca.get("state_vars", set()) | cb.get("state_vars", set())
                touched = {t for t in touched if t in state_scope}
                if not touched:
                    continue
                # CORE PREDICATE 5: sibling must be UNGUARDED, and no shared/
                # global lock spans the two modules.
                if _fn_is_guarded(b_fn):
                    continue
                shared = _global_lock_tokens(a_fn) & _global_lock_tokens(b_fn)
                if shared:
                    continue
                for tok in sorted(touched):
                    key = (ca["file"], ca["name"], a_fn["name"],
                           cb["file"], cb["name"], b_fn["name"], tok)
                    if key in seen:
                        continue
                    seen.add(key)
                    is_write = tok in b_writes
                    sub = ("cross-module-write-reentrancy" if is_write
                           else "cross-module-readonly-reentrancy")
                    note = (
                        f"during {ca['name']}.{a_fn['name']}'s callback window "
                        f"({ca['file']}:{w['cb_line']}), an attacker can re-enter "
                        f"sibling {cb['name']}.{b_fn['name']} ({cb['file']}:"
                        f"{b_fn['line']}, no reentrancy guard, relation={rel}), "
                        f"which {'writes' if is_write else 'reads'} coupled state "
                        f"'{tok}' that the window fn writes in flight; per-module "
                        f"CEI does not protect the cross-module invariant on '{tok}'"
                    )
                    hypotheses.append({
                        "workspace": str(ws),
                        "language": "sol",
                        "window_file": ca["file"],
                        "window_contract": ca["name"],
                        "window_function": a_fn["name"],
                        "window_line": w["cb_line"],
                        "callback_evidence": w["snippet"],
                        "sibling_file": cb["file"],
                        "sibling_contract": cb["name"],
                        "sibling_function": b_fn["name"],
                        "sibling_line": b_fn["line"],
                        "coupled_token": tok,
                        "relation": rel,
                        "sibling_touch": "write" if is_write else "read",
                        "sub_class": sub,
                        "note": note,
                        "attack_class": "cross-module-reentrancy",
                        "source": "CMSR",
                        "verdict": "needs-fuzz",
                        "dedup_hint_same_contract": False,
                    })

    return hypotheses


# ---------------------------------------------------------------------------
# Advisory summary (importable). Advisory-first: OFF unless explicitly asked;
# NEVER fails closed, NEVER auto-credits.
# ---------------------------------------------------------------------------
_ADVISORY_ENV = "AUDITOOOR_CMSR_A7"


def evaluate(ws: Path | str) -> dict[str, Any]:
    """Return an advisory summary. When the advisory env is set, also emit the
    jsonl sidecar. Absent the env, returns {'cross_module_sibling_reentrancy':
    None} (advisory OFF) and writes nothing - never fail-closed."""
    ws = Path(ws).resolve()
    if os.environ.get(_ADVISORY_ENV) not in ("1", "true", "TRUE", "on"):
        return {"cross_module_sibling_reentrancy": None}
    hyps = produce_hypotheses(ws)
    out = run(ws, hypotheses=hyps)
    return {
        "cross_module_sibling_reentrancy": {
            "enabled": True,
            "verdict": "needs-fuzz",
            "count": len(hyps),
            "sidecar": str(out),
        }
    }


# ---------------------------------------------------------------------------
# run() - write the JSONL sidecar.
# ---------------------------------------------------------------------------
def run(
    ws: Path | str,
    out_path: Path | str | None = None,
    hypotheses: list[dict[str, Any]] | None = None,
) -> Path:
    ws = Path(ws).resolve()
    if hypotheses is None:
        hypotheses = produce_hypotheses(ws)
    out = (
        Path(out_path)
        if out_path is not None
        else ws / ".auditooor" / "cross_module_sibling_reentrancy.jsonl"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for h in hypotheses:
            fh.write(json.dumps(h) + "\n")
    return out


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------
def _main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="CMSR (A7): cross-module reentrancy / callback-into-SIBLING "
                    "advisory screen (needs-fuzz, no auto-credit)."
    )
    p.add_argument("workspace", help="Workspace root path")
    p.add_argument("--out", default=None, help="Override output .jsonl path")
    args = p.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 1

    hyps = produce_hypotheses(ws)
    out = run(ws, args.out, hyps)
    print(f"CMSR: {len(hyps)} cross-module-sibling reentrancy hypotheses -> {out}")
    sub: dict[str, int] = {}
    for h in hyps:
        sub[h["sub_class"]] = sub.get(h["sub_class"], 0) + 1
    for k, v in sorted(sub.items()):
        print(f"  sub_class={k}: {v}")
    for h in hyps[:20]:
        print(f"  [{h['relation']}] {h['window_contract']}.{h['window_function']} "
              f"(win {h['window_file']}:{h['window_line']}) -> "
              f"{h['sibling_contract']}.{h['sibling_function']} "
              f"touches '{h['coupled_token']}' ({h['sibling_touch']})")
    if len(hyps) > 20:
        print(f"  ... ({len(hyps) - 20} more)")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
