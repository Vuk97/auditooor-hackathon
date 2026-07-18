#!/usr/bin/env python3
"""coupled-state-completeness.py - the COUPLED-STATE COMPLETENESS hunt dimension.

Mirrors tools/guard-negative-space-analyzer.py (mechanical extract -> worklist ->
agentic probe -> ingest -> --check), but over state SETS instead of guards. It
catches the Aptos-class desync: a path mutates a strict SUBSET of a set of state
that must move together (Aptos Path B omits ty_tag_cache while sibling Path A
calls flush_all_caches). This defect is invisible to (asset x function x impact)
per-function hunting because it is the DISAGREEMENT between two sibling paths.

Coupled-set signals implemented (tick1: the flush/invalidate axis - the exact
Aptos shape):
  - FLUSH-SET: within a file, the universe of receivers ever INDIVIDUALLY
    flushed/cleared/invalidated/reset/purged/evicted. A brace-block that mutates a
    strict SUBSET of that universe -> worklist row (omits = universe - block_set).
  - AGGREGATE-PARITY: a block enumerating >=2 individual invalidations while a
    sibling path calls an aggregate `*_all` -> the enumerated path may omit a
    member the aggregate covers (the exact Aptos Path-B parity risk).

Each row is a PROMPT: the mechanical extract deliberately over-includes; the
agentic probe (--ingest) rules out false positives. --check is fail-closed: every
worklist row needs a probe verdict.

Usage:
  --workspace <ws> --emit-worklist     derive coupled sets -> coupled_state_worklist.jsonl
  --workspace <ws> --ingest <verdicts> fold agent verdicts -> coupled_state_gaps.jsonl
  --workspace <ws> --check             cert verdict + open-row count
  --file <f> --emit-worklist           (test) scan a single file, print rows to stdout
  --source <dir> --emit-worklist       (test) scan a dir of source files
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

WORKLIST_SCHEMA = "auditooor.coupled_state_worklist.v1"
GAPS_SCHEMA = "auditooor.coupled_state_gaps.v1"
_SOURCE_EXTS = {".sol", ".go", ".rs", ".move"}
_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "test",
              "tests", "test_fixtures", "__pycache__", "out", "cache", "lib",
              "node_modules", "mock", "mocks"}

_METHOD_RE = re.compile(r"\.\s*([a-z_][a-z0-9_]*)\s*\(")
_RECV_TAIL_RE = re.compile(r"([A-Za-z_]\w*)\s*(?:\(\s*\))?\s*$")
_MEMBER_OPS = ("flush", "clear", "invalidate", "reset", "purge", "evict")
_AGG_SUFFIXES = ("_all", "_all_caches")
_AGG_NAMES = {"flush_all", "flush_all_caches", "clear_all", "invalidate_all",
              "reset_all", "purge_all", "evict_all", "flush_caches", "clear_caches"}
_NESTED_BRACE_RE = re.compile(r"\{[^{}]*\}")


def _classify(method: str) -> str:
    if method in _AGG_NAMES or method.endswith(_AGG_SUFFIXES):
        return "aggregate"
    if method in _MEMBER_OPS:
        return "member"
    for op in _MEMBER_OPS:
        if method.startswith(op + "_"):
            return "member"
    return "none"


def _blocks(src: str):
    stack, spans = [], []
    for idx, ch in enumerate(src):
        if ch == "{":
            stack.append(idx)
        elif ch == "}" and stack:
            s = stack.pop()
            spans.append((s, idx))
    for s, e in spans:
        yield src[:s].count("\n") + 1, src[s:e + 1]


def _strip_nested(block: str) -> str:
    inner = block[1:-1] if block.startswith("{") else block
    prev = None
    while prev != inner:
        prev = inner
        inner = _NESTED_BRACE_RE.sub(" ", inner)
    return inner


def _profile(text: str):
    members, has_agg = set(), False
    for m in _METHOD_RE.finditer(text):
        kind = _classify(m.group(1))
        if kind == "aggregate":
            has_agg = True
        elif kind == "member":
            rm = _RECV_TAIL_RE.search(text[:m.start()])
            members.add(rm.group(1) if rm else "?")
    return members, has_agg


def _rows_for_source(src: str, rel: str, co_indexed: bool = False) -> list[dict]:
    """Emit coupled-state worklist rows for one file: flush/invalidate axis (a),
    paired-stem writer-set asymmetry (c), and domain-coupling / derived-from (d).

    Heuristic (d) is the Sei/Aptos DOMAIN coupling (tx-version<->store<->commit;
    a cache keyed-by/derived-from an index). It is deliberately witnessed-only: a
    pair is coupled ONLY when the code itself contains a derivation `A = expr(B)`
    (or an explicit co-index) - never on name similarity alone - so it does not
    flood a 17k-unit Go codebase with naming false positives."""
    rows = (_flush_rows(src, rel) + _paired_stem_rows(src, rel)
            + _domain_coupling_rows(src, rel, co_indexed=co_indexed))
    # M1: Move Coin/Balance value-conservation lane - advisory, env-gated OFF by
    # default (needs-fuzz hypotheses, no auto-credit); only .move sources.
    if rel.lower().endswith(".move") and os.environ.get(
            MOVE_CONSERVATION_ENV) == "1":
        rows += _move_coin_conservation_rows(src, rel)
    return rows


def _flush_rows(src: str, rel: str) -> list[dict]:
    """Flush/invalidate-set completeness (the exact Aptos shape)."""
    blocks = []
    for line, block in _blocks(src):
        members, has_agg = _profile(_strip_nested(block))
        if members or has_agg:
            blocks.append((line, members, has_agg))
    if not blocks:
        return []
    universe = set()
    for _l, m, _a in blocks:
        universe |= m
    file_has_agg = any(a for _l, _m, a in blocks)
    if len(universe) < 2 and not file_has_agg:
        return []

    rows, seen = [], set()
    for line, members, has_agg in blocks:
        if has_agg or len(members) < 2:
            continue
        # signal A: a sibling block flushes a strict superset
        superset = None
        for _l2, om, _a2 in blocks:
            if members < om and (superset is None or len(om) > len(superset)):
                superset = om
        if superset is not None:
            omits = sorted(superset - members)
            kind, note = "flush-set", (
                f"a sibling block invalidates the superset {sorted(superset)}")
        elif file_has_agg:
            omits = sorted(universe - members)
            kind, note = "aggregate-parity", (
                "a sibling path invalidates via an aggregate *_all")
        else:
            continue
        key = (rel, line, tuple(sorted(members)), kind)
        if key in seen:
            continue
        seen.add(key)
        set_id = hashlib.sha1(f"{rel}:{line}:{kind}".encode()).hexdigest()[:12]
        rows.append({
            "schema_version": WORKLIST_SCHEMA,
            "set_id": set_id,
            "set_kind": kind,
            "set_members": sorted(universe if kind == "aggregate-parity" else superset),
            "writer_file": rel,
            "writer_line": line,
            "mutates": sorted(members),
            "omits": omits,
            "question": (
                f"This path (block @L{line} in {rel}) invalidates {sorted(members)}; "
                f"{note}. If these caches/state are COUPLED (one keyed by / derived "
                f"from another), does omitting {omits or 'a member the aggregate covers'} "
                f"leave a stale entry a downstream consumer trusts - and is this path "
                f"attacker-reachable? (Aptos struct-hijack shape.)"),
            "probe_verdict": "",
        })
    return rows


# ---- paired-stem writer-set asymmetry (Strata/NUVA-relevant: two ops that must
# ---- touch the same state; a member that writes a strict SUBSET desyncs it) ----
_FN_HEADER_RE = re.compile(
    r"^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+|unsafe\s+|const\s+|external\s+|"
    r"public\s+|internal\s+|private\s+|virtual\s+|view\s+|function\s+)*"
    r"(?:fn|func|function)?\s*(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*"
    r"(?:<[^>]*>)?\s*\(")
# names that are control-flow keywords, never real functions (avoid `if (`/`for (`
# blocks being parsed as functions).
_NOT_A_FN = {"if", "for", "while", "switch", "catch", "else", "return", "do",
             "match", "loop", "require", "assert", "emit", "revert"}
_PAIRS = [
    ("add", "remove"), ("enable", "disable"), ("grant", "revoke"),
    ("mint", "burn"), ("lock", "unlock"), ("register", "deregister"),
    ("deposit", "withdraw"), ("increase", "decrease"), ("open", "close"),
    ("stake", "unstake"), ("credit", "debit"), ("set", "unset"),
    ("acquire", "release"), ("attach", "detach"), ("link", "unlink"),
    # Move resource-linearity pair: a `split*`/`merge*` of a Coin/Balance must keep
    # the same value state coupled (sum(parts) == whole).
    ("split", "merge"),
]
_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]|\.\s*[A-Za-z_]\w*)*\s*(?:[+\-*/|&^]|<<|>>)?=(?!=)")
_CALLWRITE_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\.\s*(?:push|pop|set|update|insert|remove|delete|add|sub|"
    r"mint|burn|increment|decrement|store|save|put|write)\s*\(")
_DELETE_RE = re.compile(r"\bdelete\s+([A-Za-z_]\w*)")
_WRITE_STOP = {"if", "for", "while", "return", "let", "var", "const", "require",
               "assert", "emit", "i", "j", "k", "n", "tmp", "temp", "_", "self",
               "this", "msg", "result", "res", "ok", "err", "e", "x", "y",
               # Solidity unit / literal keywords (never coupled state)
               "wei", "gwei", "ether", "seconds", "minutes", "hours", "days",
               "weeks", "true", "false", "type", "new", "delete",
               # common Go/plumbing local names (context, timers, buffers, io) -
               # excluding KNOWN-NOISE identifiers, not inferring couplings by name
               "ctx", "context", "start", "begin", "now", "buf", "resp", "req",
               "iter", "cur", "reader", "writer", "conn", "wg", "mu", "lock"}


def _functions(src: str):
    lines = src.splitlines()
    i = 0
    while i < len(lines):
        m = _FN_HEADER_RE.match(lines[i])
        if not m or m.group("name") in _NOT_A_FN:
            i += 1
            continue
        name, depth, started, body, j = m.group("name"), 0, False, [], i
        while j < len(lines):
            ln = lines[j]
            depth += ln.count("{") - ln.count("}")
            body.append(ln)
            if "{" in ln:
                started = True
            if started and depth <= 0:
                break
            j += 1
        yield name, i + 1, "\n".join(body)
        i = j + 1 if j > i else i + 1


_LOCAL_DECL_RE = re.compile(
    r"(?:^|[;{}(,]|\breturns?\b|=>|\bfor\b|\bif\b|&&|\|\|)\s*"
    r"(?:uint\d*|int\d*|address|bool|byte|bytes\d*|string|var|let|const|"
    r"mapping\s*\([^)]*\)|[A-Z][A-Za-z0-9_]*(?:\[\])?)"
    r"(?:\s+(?:memory|storage|calldata|payable|mut|immutable))*"
    r"\s+([A-Za-z_]\w*)\s*(?:=(?!=)|;|,|\))")
_GO_WALRUS_RE = re.compile(r"\b([A-Za-z_]\w*)\s*:=")


def _local_decls(body: str) -> set[str]:
    """Names DECLARED as locals in this body (typed decl or Go :=). A coupled
    STATE set is persistent storage - a fresh local `uint256 x = ...` is NOT state,
    so the paired/flush comparison must not count it (else deposit/withdraw look
    'asymmetric' merely because they name different local amounts)."""
    d: set[str] = set()
    for m in _LOCAL_DECL_RE.finditer(body):
        d.add(m.group(1))
    for m in _GO_WALRUS_RE.finditer(body):
        d.add(m.group(1))
    return d


_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"' + r"|'(?:\\.|[^'\\])*'" + r"|`[^`]*`")


def _strip_comments(body: str) -> str:
    return _LINE_COMMENT_RE.sub("", _BLOCK_COMMENT_RE.sub(" ", body))


def _strip_strings(body: str) -> str:
    """Blank out string/char/raw-string literals so words INSIDE them (e.g. an
    error message `errors.New("timestamp older than parent")`) are never mistaken
    for coupled-state identifiers. This is the #1 domain-coupling FP source."""
    return _STRING_RE.sub('""', body)


def _state_writes(body: str) -> set[str]:
    body = _strip_comments(body)
    locals_ = _local_decls(body)
    w: set[str] = set()
    # Bare/compound/member/index assignments to an EXISTING (non-local) target are
    # storage writes; a declared local is excluded.
    for m in _ASSIGN_RE.finditer(body):
        v = m.group(1)
        if not v or v[0].isdigit() or v.lower() in _WRITE_STOP or v in locals_:
            continue
        w.add(v)
    # collection / delete writes always target persistent state (never a fresh local)
    for rx in (_CALLWRITE_RE, _DELETE_RE):
        for m in rx.finditer(body):
            v = m.group(1)
            if v and v.lower() not in _WRITE_STOP and not v[0].isdigit() \
                    and v not in locals_:
                w.add(v)
    return w


def _paired_stem_rows(src: str, rel: str) -> list[dict]:
    fns = {}
    for name, line, body in _functions(src):
        fns[name] = (line, _state_writes(body))
    rows, seen = [], set()
    for name, (line, writes) in fns.items():
        low = name.lower()
        for a, b in _PAIRS:
            for pos, neg in ((a, b), (b, a)):
                if low.startswith(pos):
                    stem = name[len(pos):]
                    for cand in (neg + stem, neg + stem.capitalize(),
                                 neg + "_" + stem.lstrip("_")):
                        if cand in fns and cand != name:
                            ow_line, ow = fns[cand]
                            if not writes or not ow or writes == ow:
                                continue
                            omits = sorted(ow - writes)
                            if not omits:
                                continue
                            key = tuple(sorted((name, cand)))
                            if key in seen:
                                continue
                            seen.add(key)
                            union = sorted(writes | ow)
                            sid = hashlib.sha1(
                                f"{rel}:{key}".encode()).hexdigest()[:12]
                            rows.append({
                                "schema_version": WORKLIST_SCHEMA,
                                "set_id": sid,
                                "set_kind": "paired-stem",
                                "set_members": union,
                                "writer_file": rel,
                                "writer_line": line,
                                "mutates": sorted(writes),
                                "omits": omits,
                                "question": (
                                    f"Paired ops `{name}` and `{cand}` in {rel} must "
                                    f"keep the same state coupled, but `{name}` writes "
                                    f"{sorted(writes)} while `{cand}` also writes "
                                    f"{omits}. Does `{name}` omitting {omits} leave "
                                    f"that state desynced (stale entry / broken "
                                    f"conservation) - and is that reachable? "
                                    f"(coupled-state partial-update.)"),
                                "probe_verdict": "",
                            })
    return rows


# ---- heuristic (d): DOMAIN coupling - keyed-by / derived-from data-flow. ----
# The Aptos TypeTagCache is keyed-by StructNameIndex; Strata NAV is derived-from
# senior/junior components; Sei's commit-set is derived-from per-version writes. A
# cell A that is DERIVED FROM a cell B must be re-established whenever B moves; a
# writer that mutates B but omits A leaves A stale. We only treat (A,B) as coupled
# when the source WITNESSES the derivation `A = <expr referencing B>` - never on
# names alone (anti-flood: a 17k-unit Go tree must not fire on naming heuristics).
_RECEIVERS = {"self", "this"}
_WORD_RE = re.compile(r"[A-Za-z_]\w*")
# RHS tokens that are computation noise, not coupled state.
_DERIV_NOISE = {"len", "min", "max", "abs", "new", "make", "append", "keccak256",
                "uint256", "int256", "uint", "int", "address", "bool", "true",
                "false", "require", "assert", "if", "else", "return", "as", "type",
                "memory", "storage", "calldata", "sender", "value", "now", "block",
                "msg", "self", "this", "super"}
_DERIV_ASSIGN_RE = re.compile(
    r"(?:^|[;{}\n)])\s*([A-Za-z_]\w*)((?:\s*\.\s*[A-Za-z_]\w*|\s*\[[^\]]*\])*)\s*"
    r"(?:[+\-*/|&^]|<<|>>)?=(?!=)\s*([^;{}\n]+)")
_ASSIGN_FULL_RE = re.compile(
    r"\b([A-Za-z_]\w*)((?:\s*\.\s*[A-Za-z_]\w*|\s*\[[^\]]*\])*)\s*"
    r"(?:[+\-*/|&^]|<<|>>)?=(?!=)")
_INCDEC_RE = re.compile(
    r"\b([A-Za-z_]\w*)((?:\s*\.\s*[A-Za-z_]\w*|\s*\[[^\]]*\])*)\s*(?:\+\+|--)")
_INDEX_KEY_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\[([^\]]+)\]"
    r"(?:\s*\.\s*[A-Za-z_]\w*|\s*\[[^\]]*\])*\s*(?:[+\-*/|&^]|<<|>>)?=(?!=)")
_LENS_HINTS = ("lens", "view", "interface", "abstract", "/i", "mock", "getter")


def _cell_name(base: str, tail: str) -> str:
    """Normalize an assignment target to its storage CELL: `self.ty_tag_cache` ->
    ty_tag_cache, `s.version` -> version (short Go receiver), `balances[k]` ->
    balances, bare `x` -> x."""
    fields = re.findall(r"\.\s*([A-Za-z_]\w*)", tail or "")
    if fields and (base in _RECEIVERS or (len(base) <= 2 and base.islower())):
        return fields[-1]
    return base


def _param_names(body: str) -> set[str]:
    """Identifier tokens inside the signature parens (receiver + params + named
    returns). Go passes `header *Header` with no `:=`, so _local_decls misses
    params - they must still be excluded from the state set (they are locals, not
    storage). Over-includes type tokens too, which are harmless to exclude."""
    header = body[:body.find("{")] if "{" in body else body
    names: set[str] = set()
    depth, start = 0, -1
    for i, ch in enumerate(header):
        if ch == "(":
            if depth == 0:
                start = i + 1
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
            if depth == 0 and start >= 0:
                names.update(re.findall(r"[A-Za-z_]\w*", header[start:i]))
                start = -1
    return names


def _state_cells(body: str) -> set[str]:
    """FIELD-aware state-write set for heuristic (d): unlike _state_writes (which
    records the receiver base), this normalizes `s.version = ` to the cell
    `version` so receiver-style Go/Rust couplings are visible. Excludes locals
    (typed decls, Go `:=`, AND signature params/receiver/named-returns)."""
    body = _strip_strings(_strip_comments(body))
    locals_ = _local_decls(body) | _param_names(body)
    cells: set[str] = set()
    for rx in (_ASSIGN_FULL_RE, _INCDEC_RE):
        for m in rx.finditer(body):
            c = _cell_name(m.group(1), m.group(2))
            if c and not c[0].isdigit() and c.lower() not in _WRITE_STOP \
                    and c not in locals_ and len(c) >= 3:
                cells.add(c)
    for rx in (_CALLWRITE_RE, _DELETE_RE):
        for m in rx.finditer(body):
            c = m.group(1)
            if c and not c[0].isdigit() and c.lower() not in _WRITE_STOP \
                    and c not in locals_ and len(c) >= 3:
                cells.add(c)
    return cells


def _domain_coupling_rows(src: str, rel: str, co_indexed: bool = False) -> list[dict]:
    low_rel = rel.lower()
    if any(h in low_rel for h in _LENS_HINTS):
        return []
    fn_cells: dict[str, tuple[int, set[str]]] = {}
    fn_index: dict[str, dict[str, set[str]]] = {}  # fn -> {map: {keyexpr}}
    for name, line, body in _functions(src):
        b = _strip_strings(_strip_comments(body))
        fn_cells[name] = (line, _state_cells(body))
        if co_indexed:
            keys: dict[str, set[str]] = {}
            for m in _INDEX_KEY_RE.finditer(b):
                mp = m.group(1)
                if mp.lower() in _WRITE_STOP or len(mp) < 3:
                    continue
                keys.setdefault(mp, set()).add(re.sub(r"\s+", "", m.group(2)))
            fn_index[name] = keys
    all_cells: set[str] = set()
    writer_count: dict[str, int] = {}
    for _l, cs in fn_cells.values():
        all_cells |= cs
        for c in cs:
            writer_count[c] = writer_count.get(c, 0) + 1
    if len(all_cells) < 2:
        return []
    # Persistence proxy: real coupled STATE is mutated by >=2 distinct functions.
    # A locally-built struct (geth `header.GasLimit = ...`, a ctor's `&Block{}`)
    # has its fields written in ONE function -> excluded. This kills the Go
    # local-struct-field FP class without needing full alias/type analysis.
    multi = {c for c, n in writer_count.items() if n >= 2}

    # 1) DERIVED pairs A<-B witnessed by `A = <expr with B>` anywhere in the file.
    derived: dict[str, set[str]] = {}
    full = _strip_strings(_strip_comments(src))
    for m in _DERIV_ASSIGN_RE.finditer(full):
        a = _cell_name(m.group(1), m.group(2))
        if a not in all_cells or len(a) < 3:
            continue
        for w in set(_WORD_RE.findall(m.group(3))):
            if w == a or len(w) < 3 or w.lower() in _DERIV_NOISE:
                continue
            if w in all_cells:
                derived.setdefault(a, set()).add(w)

    rows, seen = [], set()
    for a, sources in derived.items():
        for b in sorted(sources):
            # b must be genuine multi-writer state (not a single-fn local struct).
            if b not in multi:
                continue
            # symmetry check: is A re-established in EVERY writer of B? if so, safe.
            b_writers = [(n, ln) for n, (ln, cs) in fn_cells.items() if b in cs]
            if len(b_writers) < 2:
                continue
            if all(a in fn_cells[n][1] for n, _ln in b_writers):
                continue  # A always moves with B -> maintained, no desync
            for n, ln in b_writers:
                if a in fn_cells[n][1]:
                    continue  # this writer keeps them in sync
                key = (rel, a, b, n)
                if key in seen:
                    continue
                seen.add(key)
                sid = hashlib.sha1(
                    f"{rel}:derived:{a}:{b}:{n}".encode()).hexdigest()[:12]
                rows.append({
                    "schema_version": WORKLIST_SCHEMA,
                    "set_id": sid,
                    "set_kind": "derived-coupling",
                    "set_members": sorted({a, b}),
                    "writer_file": rel,
                    "writer_line": ln,
                    "mutates": [b],
                    "omits": [a],
                    "question": (
                        f"`{a}` is DERIVED-FROM `{b}` (a `{a} = f({b})` derivation "
                        f"exists in {rel}), so they are coupled. But `{n}` (@L{ln}) "
                        f"mutates `{b}` WITHOUT re-establishing `{a}`. Does that leave "
                        f"`{a}` stale for a downstream consumer (mispricing / "
                        f"type-confusion / consensus-split), and is `{n}` "
                        f"attacker-reachable? (keyed-by/derived-from desync - "
                        f"Aptos/Sei domain-coupling shape.)"),
                    "probe_verdict": "",
                })

    # 2) CO-INDEXED maps (opt-in, --co-indexed): two maps written with the SAME key
    # in one fn => co-indexed; a fn that writes one but never the other desyncs.
    # Default OFF: on a large tree balances[u]/allowances[u] would over-fire; this
    # lane is for targeted study (e.g. Sei multiversion store) not the default sweep.
    if co_indexed:
        pairs: set[tuple[str, str]] = set()
        for keys in fn_index.values():
            maps = list(keys.items())
            for i in range(len(maps)):
                for j in range(i + 1, len(maps)):
                    if keys[maps[i][0]] & keys[maps[j][0]]:
                        pairs.add(tuple(sorted((maps[i][0], maps[j][0]))))
        for m1, m2 in sorted(pairs):
            for a, b in ((m1, m2), (m2, m1)):
                for n, keys in fn_index.items():
                    if b in keys and a not in keys and a not in fn_cells[n][1]:
                        key = (rel, a, b, n, "coidx")
                        if key in seen:
                            continue
                        seen.add(key)
                        ln = fn_cells[n][0]
                        sid = hashlib.sha1(
                            f"{rel}:coidx:{a}:{b}:{n}".encode()).hexdigest()[:12]
                        rows.append({
                            "schema_version": WORKLIST_SCHEMA,
                            "set_id": sid,
                            "set_kind": "co-indexed",
                            "set_members": sorted({a, b}),
                            "writer_file": rel,
                            "writer_line": ln,
                            "mutates": [b],
                            "omits": [a],
                            "question": (
                                f"`{a}` and `{b}` are co-indexed by the same key "
                                f"elsewhere in {rel} (must move together), but `{n}` "
                                f"(@L{ln}) updates `{b}[key]` without `{a}[key]`. Does "
                                f"that desync the two maps (stale/missing entry), and "
                                f"is `{n}` reachable? (co-indexed store desync - Sei "
                                f"multiversion / tx-version<->store shape.)"),
                            "probe_verdict": "",
                        })
    return rows


# ---- Move value-conservation (M1): resource-linearity sum(parts) == whole. ----
# A Move Coin<T>/Balance<T> carries a `value` field and is trusted to CONSERVE:
# splitting `amount` off a `&mut Coin` whole must pair the created part with a
# decrement of the whole (`whole.value = whole.value - amount`). A `split`-shaped
# fn that packs a value-bearing part but OMITS the whole decrement mints value
# (sum(parts) > whole) - one leg updated without the paired join. This is NOT the
# A9 cross-fn interruption/partial-write-of-a-SET class; M1 is the arithmetic
# conservation LAW of Move resource linearity, witnessed INSIDE one split body.
# Advisory-first + env-gated OFF (AUDITOOOR_MOVE_CONSERVATION=1); rows carry
# hypothesis_verdict='needs-fuzz' with an EMPTY probe_verdict (NO auto-credit).
MOVE_CONSERVATION_ENV = "AUDITOOOR_MOVE_CONSERVATION"
_MOVE_FN_RE = re.compile(
    r"^\s*(?:public(?:\s*\([^)]*\))?\s+)?(?:entry\s+)?(?:native\s+)?"
    r"fun\s+([A-Za-z_]\w*)")
# a `&mut Coin`/`&mut Balance` parameter: the WHOLE that a split must decrement.
_MOVE_WHOLE_RE = re.compile(
    r"([A-Za-z_]\w*)\s*:\s*&mut\s+(?:[A-Za-z_]\w*::)*(Coin|Balance)\b")
# a value-bearing pack `Coin<T> { value: amount }` (create a part carrying value).
_MOVE_PACK_RE = re.compile(
    r"\b(?:Coin|Balance)\s*(?:<[^>]*>)?\s*\{\s*value\s*:\s*([A-Za-z_]\w*)\b")


def _move_functions(src: str):
    """Yield (name, 1-based line, body) for Move `fun`s with a brace body."""
    lines = src.splitlines()
    i = 0
    while i < len(lines):
        m = _MOVE_FN_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name, depth, started, body, j = m.group(1), 0, False, [], i
        while j < len(lines):
            ln = lines[j]
            depth += ln.count("{") - ln.count("}")
            body.append(ln)
            if "{" in ln:
                started = True
            if started and depth <= 0:
                break
            j += 1
        if started:
            yield name, i + 1, "\n".join(body)
        i = j + 1 if j > i else i + 1


def _move_whole_decremented(whole: str, body: str) -> bool:
    """True if `<whole>.value` is decremented in `body` (the paired split join):
    `whole.value = whole.value - ...`, `whole.value -= ...`, or a *::split/extract
    on the whole (which decrements it under the hood)."""
    w = re.escape(whole)
    if re.search(w + r"\.value\s*=\s*[^;{}\n]*-\s*", body):
        return True
    if re.search(w + r"\.value\s*-=", body):
        return True
    # delegated decrement: coin::split(whole, ..) / coin::extract(&mut whole, ..)
    if re.search(r"(?:split|extract|withdraw)\s*\(\s*&?mut\s+" + w + r"\b", body):
        return True
    return False


def _move_coin_conservation_rows(src: str, rel: str) -> list[dict]:
    """M1: flag a Move split-shaped fn that packs a value-bearing part off a
    `&mut Coin/Balance` whole but omits the paired whole-decrement join. Emits a
    needs-fuzz hypothesis (NO auto-credit). FP-guards: skip zero-value packs (empty
    coin ctor), skip when the whole IS decremented (clean split), skip fns with no
    `&mut Coin/Balance` whole (an authorized `mint` legitimately creates value)."""
    body_src = _strip_comments(src)
    rows, seen = [], set()
    for name, line, body in _move_functions(body_src):
        header = body[:body.find("{")] if "{" in body else body
        wholes = [(w, ty) for w, ty in _MOVE_WHOLE_RE.findall(header)]
        if not wholes:
            continue  # no source whole -> mint/zero ctor, not a split desync
        # value-bearing packs with a NON-zero variable amount created in the body
        packs = [amt for amt in _MOVE_PACK_RE.findall(body) if amt != "0"]
        if not packs:
            continue
        # clean iff SOME whole is decremented (the paired join is present)
        if any(_move_whole_decremented(w, body) for w, _ty in wholes):
            continue
        whole, ty = wholes[0]
        amt = packs[0]
        key = (rel, name)
        if key in seen:
            continue
        seen.add(key)
        sid = hashlib.sha1(
            f"{rel}:move-conserve:{name}".encode()).hexdigest()[:12]
        rows.append({
            "schema_version": WORKLIST_SCHEMA,
            "set_id": sid,
            "set_kind": "move-coin-conservation",
            "set_members": sorted({f"{whole}.value", "part.value"}),
            "writer_file": rel,
            "writer_line": line,
            "mutates": ["part.value"],
            "omits": [f"{whole}.value"],
            "advisory": True,
            "hypothesis_verdict": "needs-fuzz",
            "question": (
                f"Move `{name}` in {rel} packs a value-bearing {ty} part "
                f"(`{{ value: {amt} }}`) off the &mut whole `{whole}` but never "
                f"decrements `{whole}.value` by the same amount. Does that break "
                f"resource-linearity sum(parts) == whole (value MINTED / burned), "
                f"and is `{name}` reachable? (Move Coin value-conservation desync - "
                f"needs-fuzz, no auto-credit.)"),
            "probe_verdict": "",
        })
    return rows


def _load_inscope_files(ws: Path) -> list[str]:
    p = ws / ".auditooor" / "inscope_units.jsonl"
    if not p.is_file():
        return []
    files, seen = [], set()
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        fp = None
        if d.get("unit") and "::" in str(d["unit"]):
            fp = str(d["unit"]).rsplit("::", 1)[0]
        elif d.get("file"):
            fp = str(d["file"])
        if not fp:
            continue
        rel = fp.strip().lstrip("./")
        if not rel or rel in seen or Path(rel).suffix.lower() not in _SOURCE_EXTS:
            continue
        if any(part in _SKIP_DIRS for part in Path(rel).parts):
            continue
        seen.add(rel)
        files.append(rel)
    return files


def _emit_worklist(ws: Path | None, single: Path | None, source: Path | None,
                   co_indexed: bool = False) -> int:
    rows: list[dict] = []
    if single:
        rows = _rows_for_source(single.read_text(errors="replace"), str(single),
                                co_indexed=co_indexed)
    elif source:
        for f in sorted(source.rglob("*")):
            if f.suffix.lower() in _SOURCE_EXTS and not any(
                    p in _SKIP_DIRS for p in f.parts):
                rows += _rows_for_source(f.read_text(errors="replace"),
                                         str(f.relative_to(source)),
                                         co_indexed=co_indexed)
    elif ws:
        for rel in _load_inscope_files(ws):
            fp = ws / rel
            if fp.is_file():
                rows += _rows_for_source(fp.read_text(errors="replace"), rel,
                                         co_indexed=co_indexed)
    if ws:
        out = ws / ".auditooor" / "coupled_state_worklist.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(json.dumps(r, sort_keys=True) for r in rows) +
                       ("\n" if rows else ""), encoding="utf-8")
        print(f"[coupled-state] emitted {len(rows)} worklist row(s) -> {out}")
    else:
        for r in rows:
            print(json.dumps(r, sort_keys=True))
        print(f"[coupled-state] {len(rows)} row(s)", file=sys.stderr)
    return 0


def _ingest(ws: Path, verdicts: Path) -> int:
    wl = ws / ".auditooor" / "coupled_state_worklist.jsonl"
    rows = [json.loads(l) for l in wl.read_text().splitlines() if l.strip()] \
        if wl.is_file() else []
    vmap = {}
    for l in verdicts.read_text().splitlines():
        if l.strip():
            v = json.loads(l)
            if v.get("set_id"):
                vmap[v["set_id"]] = v.get("probe_verdict") or v.get("verdict") or ""
    gaps = []
    for r in rows:
        r = dict(r)
        r["probe_verdict"] = vmap.get(r["set_id"], r.get("probe_verdict", ""))
        if r["probe_verdict"]:
            gaps.append({"schema_version": GAPS_SCHEMA, **r})
    out = ws / ".auditooor" / "coupled_state_gaps.jsonl"
    out.write_text("\n".join(json.dumps(g, sort_keys=True) for g in gaps) +
                   ("\n" if gaps else ""), encoding="utf-8")
    print(f"[coupled-state] ingested {len(gaps)}/{len(rows)} verdict(s) -> {out}")
    return 0


def _check(ws: Path) -> int:
    wl = ws / ".auditooor" / "coupled_state_worklist.jsonl"
    if not wl.is_file():
        print("[coupled-state] check: no worklist (run --emit-worklist) -> PASS-vacuous")
        return 0
    rows = [json.loads(l) for l in wl.read_text().splitlines() if l.strip()]
    # a row is PROBED if its own verdict is set OR the gaps file (from --ingest)
    # carries a non-empty verdict for its set_id.
    gaps = ws / ".auditooor" / "coupled_state_gaps.jsonl"
    probed: set[str] = set()
    if gaps.is_file():
        for l in gaps.read_text().splitlines():
            if l.strip():
                g = json.loads(l)
                if g.get("set_id") and g.get("probe_verdict"):
                    probed.add(g["set_id"])
    open_rows = [r for r in rows
                 if not r.get("probe_verdict") and r.get("set_id") not in probed]
    print(f"[coupled-state] check: {len(rows)} row(s), {len(open_rows)} OPEN (unprobed)")
    if open_rows:
        print(f"NOT-DONE: {len(open_rows)} coupled-state row(s) lack a probe verdict")
        return 1
    print("pass-coupled-state-completeness")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", type=Path)
    ap.add_argument("--file", type=Path)
    ap.add_argument("--source", type=Path)
    ap.add_argument("--emit-worklist", action="store_true")
    ap.add_argument("--co-indexed", action="store_true",
                    help="also emit heuristic-(d) co-indexed-map rows (opt-in; "
                         "off by default - over-fires on large trees)")
    ap.add_argument("--ingest", type=Path)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    if a.emit_worklist:
        return _emit_worklist(a.workspace, a.file, a.source,
                              co_indexed=a.co_indexed)
    if a.ingest:
        return _ingest(a.workspace, a.ingest)
    if a.check:
        return _check(a.workspace)
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
