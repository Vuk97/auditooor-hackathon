#!/usr/bin/env python3
"""go-goroutine-lifecycle-census.py  (R12) - Go goroutine lifecycle-safety census.

WHAT THIS TOOL IS
=================
A GENERAL, target-agnostic INVARIANT / TRUST-ENFORCEMENT screen for Go node
software. It is NOT a specific bug-shape detector. It enumerates a fixed class of
CONCURRENCY ENFORCEMENT POINTS and, for each, states the private invariant the
surrounding runtime DELEGATES to that point and asks whether the invariant is
actually discharged - i.e. it applies the north-star method:

  "A TRUSTED ENFORCEMENT is bypassable or its private invariant is unsound."

THE DELEGATED-AND-TRUSTED INVARIANT (per the north-star)
-------------------------------------------------------
A Go node's process liveness and shared-state integrity are DELEGATED to three
concurrency primitives that the rest of the system TRUSTS to be sound:

  (a) SPAWN  - `go func(){...}`         private invariant: a panic inside the
      goroutine is CONTAINED (top-level defer+recover). If unsound, a panic in a
      spawned goroutine is unrecoverable by the caller and CRASHES the whole
      process (Go memory model / go.dev/ref/mem).

  (b) BLOCKING-OP - a `select {}` with no progress/cancellation escape.
      private invariant: the blocking wait has a BOUNDED escape (a `default:`, a
      `<-ctx.Done()` cancellation case, or a timer/ticker case). If unsound, the
      select can DEADLOCK / LEAK the goroutine -> liveness-DoS.

  (c) SHARED-CELL - a captured, non-receiver mutable cell WRITTEN inside a
      spawned goroutine. private invariant: concurrent access is SYNCHRONISED
      (mutex / channel ownership / atomic). If unsound, two goroutines race the
      cell -> torn/lost state (concurrent map access is not atomic).

THE ATTACK (why this is a security census, not a lint)
------------------------------------------------------
The screen is scoped to enforcement points REACHABLE FROM AN UNTRUSTED-INPUT
BOUNDARY (RPC / mempool / p2p / handler / ABCI ingress) by default, because that
is where an external adversary can DRIVE the unsound path: feed a message that
makes the un-recovered goroutine panic, that stalls the escape-less select, or
that races the unsynchronised cell -> validator/chain halt or state corruption.

GENERALITY (this is a class, not a shape)
-----------------------------------------
The three enforcement-point sets and their private invariants are fixed and
target-independent; instantiated per target from whatever Go source is in scope.
It never encodes a specific vulnerable function, protocol, or impact string.
It FUSES the two existing point-detectors (G12 unrecovered-panic-in-goroutine,
G6 goroutine-fanout-unsync-shared) into ONE lifecycle census and ADDS the
currently-uncovered blocking-liveness axis (an escape-less `select`).

ADVISORY-FIRST / NO-AUTO-CREDIT (hard contract)
-----------------------------------------------
Every emitted row carries verdict="needs-fuzz" and no_auto_credit=true. This tool
NEVER flips a gate, NEVER resolves a unit, and NEVER fail-closes: it always exits
0. Static reachability is a HYPOTHESIS; a `go test -race` / deadlock-repro run is
the confirmation lane. Hang the rows on the completeness-matrix CONCURRENCY axis;
do not silo them.

Usage:
  python3 tools/go-goroutine-lifecycle-census.py --workspace <ws> [--json]
  python3 tools/go-goroutine-lifecycle-census.py --file <a.go> [--all] [--json]
  python3 tools/go-goroutine-lifecycle-census.py --file <a.go> --arm select_no_escape

Flags:
  --workspace DIR  scan every *.go (non _test.go) under DIR.
  --file FILE      scan a single Go file (used by tests / fleet-FP spot checks).
  --all            do NOT require ingress-adjacency (emit every enforcement point).
  --arm NAME       restrict to one arm: spawn_no_recover | select_no_escape |
                   shared_cell_unsync (repeatable). Default: all three.
  --out PATH       override the hypotheses jsonl output path.
  --json           print accounting + rows as JSON to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys

TOOL = "go-goroutine-lifecycle-census"
OUT_REL = os.path.join(".auditooor",
                       "goroutine_lifecycle_safety_census_hypotheses.jsonl")
ACC_REL = os.path.join(".auditooor",
                       "goroutine_lifecycle_safety_census_accounting.json")

ARMS = ("spawn_no_recover", "select_no_escape", "shared_cell_unsync")

# --------------------------------------------------------------------------- #
# Comment / string stripping (length-preserving so byte offsets still map to   #
# original line numbers). Removes // line comments, /* */ block comments, and  #
# the CONTENTS of "", '', `` literals so their inner braces/keywords cannot    #
# perturb brace-matching or keyword search.                                    #
# --------------------------------------------------------------------------- #
def strip_comments_strings(src: str) -> str:
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            out.append("  ")
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append("  ")
                i += 2
            continue
        if c in ('"', "'", "`"):
            quote = c
            out.append(" ")
            i += 1
            while i < n and src[i] != quote:
                if quote != "`" and src[i] == "\\" and i + 1 < n:
                    out.append("  ")
                    i += 2
                    continue
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


# --------------------------------------------------------------------------- #
# Top-level function splitting. gofmt guarantees a top-level declaration        #
# starts at column 0 and its closing brace is a bare `}` at column 0.          #
# --------------------------------------------------------------------------- #
_FUNC_NAME = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z0-9_]+)")


def split_top_functions(stripped: str):
    """Yield (name, start_line_1based, text) for each top-level func."""
    lines = stripped.split("\n")
    n = len(lines)
    i = 0
    out = []
    while i < n:
        line = lines[i]
        if line.startswith("func ") or line.startswith("func("):
            start = i
            j = i + 1
            # top-level func body closes with a bare `}` at column 0.
            while j < n and lines[j] != "}":
                j += 1
            text = "\n".join(lines[start:min(j + 1, n)])
            m = _FUNC_NAME.match(line)
            name = m.group(1) if m else "?"
            out.append((name, start + 1, text))
            i = j + 1
        else:
            i += 1
    return out


def _paren_match(text: str, open_idx: int) -> int:
    depth = 0
    for k in range(open_idx, len(text)):
        if text[k] == "(":
            depth += 1
        elif text[k] == ")":
            depth -= 1
            if depth == 0:
                return k
    return -1


def _brace_match(text: str, open_idx: int) -> int:
    depth = 0
    for k in range(open_idx, len(text)):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return k
    return -1


# --------------------------------------------------------------------------- #
# Enforcement-point (a): spawned goroutine closures.                           #
# --------------------------------------------------------------------------- #
_GO_CLOSURE = re.compile(r"\bgo\s+func\s*\(")


def iter_go_closures(ftext: str):
    """Yield (spawn_offset, params, body) for each `go func(...) {...}`."""
    for m in _GO_CLOSURE.finditer(ftext):
        popen = m.end() - 1  # index of the '(' after func
        pclose = _paren_match(ftext, popen)
        if pclose < 0:
            continue
        params = ftext[popen + 1:pclose]
        bopen = ftext.find("{", pclose)
        if bopen < 0:
            continue
        bclose = _brace_match(ftext, bopen)
        if bclose < 0:
            continue
        yield m.start(), params, ftext[bopen + 1:bclose]


def closure_has_toplevel_recover(body: str) -> bool:
    """CORE PREDICATE (spawn arm). True iff the closure body contains a
    `recover(` AND a `defer` at closure-body top level (brace depth 0). A defer
    nested in an inner closure/loop is NOT the goroutine's own recover.
    """
    if "recover(" not in body.replace(" ", ""):
        return False
    depth = 0
    for mo in re.finditer(r"[{}]|\bdefer\b", body):
        tok = mo.group(0)
        if tok == "{":
            depth += 1
        elif tok == "}":
            depth -= 1
        elif depth == 0:
            return True
    return False


# --------------------------------------------------------------------------- #
# Enforcement-point (b): blocking `select {}` with no escape.                  #
# --------------------------------------------------------------------------- #
_SELECT = re.compile(r"\bselect\s*\{")
# An escape case: a `default:`, a `<-...Done()` cancellation receive, a
# timer/ticker receive (`<-t.C` / time.After / time.Tick) - all guarantee the
# select cannot block forever.
_ESC_CASE = re.compile(
    r"\bdefault\b"
    r"|<-\s*[\w.]*\.Done\s*\(\s*\)"
    r"|<-\s*[\w.()]*\.C\b"
    r"|time\.After\s*\("
    r"|time\.Tick\w*\s*\("
)
# A receive-form case, capturing the channel EXPRESSION being received from.
# Matches a bare `case <-ch:` and a bound `case v := <-ch:` /
# `case v, ok := <-ch:`; deliberately does NOT match a SEND `case ch <- v:`
# (a send is not a bounded escape).
_RECV_CASE = re.compile(
    r"^case\s+(?:[\w, ]+:?=\s*)?<-\s*(?P<ch>[A-Za-z_][\w.]*)")
# A BARE receive case: `case <-ch:` with no value binding before the arrow.
_BARE_RECV_CASE = re.compile(r"^case\s*<-\s*[A-Za-z_][\w.]*\s*:")
# Likely-cancellation channel NAME tokens (matched case-insensitively against
# the channel's last identifier segment).
_CANCEL_NAME = re.compile(r"quit|done|stop|close|exit|cancel|shutdown", re.I)
# A case body that terminates the loop -> a bare drain-then-exit is bounded.
_BODY_TERMINATES = re.compile(r"\breturn\b|\bbreak\b")


def _cancel_channel_name(chan_expr: str) -> bool:
    """True iff the received-from channel expression looks like a cancellation
    channel: its last identifier segment matches a quit/cancel name keyword, or
    has a `*Ch` suffix (e.g. quit, doneCh, ctx.Done, stopChan)."""
    seg = chan_expr.split(".")[-1].strip("()")
    if not seg:
        return False
    if _CANCEL_NAME.search(seg):
        return True
    if len(seg) > 2 and seg.endswith("Ch"):
        return True
    return False


def _select_top_case_blocks(body: str):
    """Yield (header, case_body) for the select's OWN cases (relative depth 0),
    excluding cases that belong to a nested select. `header` is the stripped
    `case ...:` / `default:` line; `case_body` is the text of the lines that
    follow it (up to the next own-case)."""
    blocks = []
    cur = None
    depth = 0
    for line in body.split("\n"):
        s = line.strip()
        is_case = depth == 0 and (s.startswith("case ") or s.startswith("case\t")
                                  or s == "default:" or s.startswith("default:")
                                  or s.startswith("default "))
        if is_case:
            if cur is not None:
                blocks.append((cur[0], "\n".join(cur[1])))
            cur = (s, [])
        elif cur is not None:
            cur[1].append(line)
        depth += line.count("{") - line.count("}")
        if depth < 0:
            depth = 0
    if cur is not None:
        blocks.append((cur[0], "\n".join(cur[1])))
    return blocks


def select_is_escaped(body: str) -> bool:
    """CORE PREDICATE (blocking arm). True iff the select has a bounded escape
    among its OWN top-level cases: a `default:`, a `<-ctx.Done()` cancellation
    receive, a timer/ticker receive (existing), a receive on a likely-
    cancellation channel (name keyword or `*Ch` suffix), or a bare `case <-ch:`
    whose body returns/breaks (a drain-then-exit shutdown case)."""
    for header, cbody in _select_top_case_blocks(body):
        if _ESC_CASE.search(header):
            return True
        m = _RECV_CASE.match(header)
        if m and _cancel_channel_name(m.group("ch")):
            return True
        if _BARE_RECV_CASE.match(header):
            tail = header.split(":", 1)[1] if ":" in header else ""
            if _BODY_TERMINATES.search(tail) or _BODY_TERMINATES.search(cbody):
                return True
    return False


def iter_selects(ftext: str):
    """Yield (offset, body) for each `select {...}`."""
    for m in _SELECT.finditer(ftext):
        bopen = ftext.find("{", m.start())
        if bopen < 0:
            continue
        bclose = _brace_match(ftext, bopen)
        if bclose < 0:
            continue
        yield m.start(), ftext[bopen + 1:bclose]


# --------------------------------------------------------------------------- #
# Enforcement-point (c): unsynchronised captured shared write in a goroutine.  #
# (Fuses G6: requires a goroutine closure + a CAPTURED non-receiver write.)    #
# --------------------------------------------------------------------------- #
_RECV = re.compile(r"^func\s*\(\s*([A-Za-z_]\w*)\s")
_SYNC_GUARD = re.compile(
    r"\.\s*R?Lock\s*\(|\.\s*R?Unlock\s*\("
    r"|\batomic\s*\.\s*(?:Store|Load|Add|Swap|CompareAndSwap)\w*\s*\("
    r"|<-\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*<-"
)
_INDEX_WRITE = re.compile(r"(?P<base>[A-Za-z_]\w*)(?:\.\w+)*\s*\[[^\]]+\]\s*=(?!=)")
_PTR_WRITE = re.compile(r"\*\s*(?P<base>[A-Za-z_]\w*)\s*=(?!=)")
_CTX_WRITE = re.compile(
    r"(?P<base>[A-Za-z_]\w*)\.(?:KVStore|Set[A-Z]\w*|Store|WithValue|"
    r"EventManager)\s*\("
)
_LOCAL_DECL_TPL = r"\b{name}\b\s*(?::=|,)|\bvar\s+{name}\b"


def closure_shared_write(cbody: str, recv, params: set):
    """CORE PREDICATE (shared-cell arm). First captured, non-receiver, non-local
    shared write in a goroutine closure body -> (kind, base, offset) or None."""
    for rx, kind in ((_INDEX_WRITE, "index"), (_PTR_WRITE, "ptr_deref"),
                     (_CTX_WRITE, "ctx_method")):
        for m in rx.finditer(cbody):
            base = m.group("base")
            if recv is not None and base == recv:
                continue
            if base in params:
                continue
            decl = re.search(_LOCAL_DECL_TPL.format(name=re.escape(base)), cbody)
            if decl is not None and decl.start() < m.start():
                continue
            return kind, base, m.start()
    return None


def has_sync_guard(text: str) -> bool:
    return _SYNC_GUARD.search(text) is not None


# --------------------------------------------------------------------------- #
# Ingress adjacency (the untrusted-input boundary gate).                       #
# --------------------------------------------------------------------------- #
_INGRESS_TEXT = re.compile(
    r"\bCheckTx\b|\bDeliverTx\b|\bRecheckTx\b|\bServeHTTP\b|\bServeMsg"
    r"|MsgServer|msgServer|\bRegisterService\b|\bReceive(?:Envelope)?\s*\("
    r"|\bReactor\b|\bmempool\b|\bMempool\b|\bp2p\b|\bgrpc\b|\bhttp\."
    r"|\babci\.|BeginBlock|EndBlock|PreBlock|RunMsg|ProcessProposal"
    r"|PrepareProposal|ExtendVote|VerifyVoteExtension|\bHandle[A-Z]\w*\s*\("
    r"|func\s+.*\bQuery[A-Z]\w*\s*\(|ServeQuery"
)
_INGRESS_PATH = re.compile(
    r"(?:^|/)(?:rpc|p2p|mempool|abci|server|handler|handlers|api|"
    r"msgserver|grpc)(?:/|_|\.go$)", re.IGNORECASE
)


def is_ingress_adjacent(ftext: str, filename: str) -> bool:
    if _INGRESS_TEXT.search(ftext):
        return True
    if _INGRESS_PATH.search(filename.replace(os.sep, "/")):
        return True
    return False


# --------------------------------------------------------------------------- #
# Analysis                                                                     #
# --------------------------------------------------------------------------- #
def _line_of(ftext: str, offset: int, fn_start_line: int) -> int:
    return fn_start_line + ftext[:offset].count("\n")


_EXPLOIT = {
    "spawn_no_recover": "process-crash-liveness",
    "select_no_escape": "goroutine-deadlock-liveness",
    "shared_cell_unsync": "data-race-state-corruption",
}
_INVARIANT = {
    "spawn_no_recover":
        "a panic inside a spawned goroutine is contained by a top-level "
        "defer+recover (else it crashes the whole process)",
    "select_no_escape":
        "a blocking select has a bounded escape (default / ctx.Done() / timer) "
        "so it cannot deadlock or leak the goroutine",
    "shared_cell_unsync":
        "a cell written across goroutines has exclusive ownership or "
        "synchronisation (mutex / channel handoff / atomic)",
}


def analyze_source(src: str, filename: str, all_scopes: bool = False,
                   arms=None):
    """Return the list of hypothesis rows for one Go source string."""
    arms = set(arms) if arms else set(ARMS)
    stripped = strip_comments_strings(src)
    rows = []
    for name, start_line, ftext in split_top_functions(stripped):
        ingress = is_ingress_adjacent(ftext, filename)
        if not all_scopes and not ingress:
            continue
        recv_m = _RECV.match(ftext)
        recv = recv_m.group(1) if recv_m else None

        # (a) SPAWN + (c) SHARED-CELL both walk goroutine closures.
        for spawn_off, params, cbody in iter_go_closures(ftext):
            pset = set(re.findall(r"[A-Za-z_]\w*", params))
            if "spawn_no_recover" in arms and not closure_has_toplevel_recover(cbody):
                rows.append(_row("spawn_no_recover", filename, name,
                                 _line_of(ftext, spawn_off, start_line),
                                 "go func(){...} spawn with no top-level recover",
                                 ingress))
            if "shared_cell_unsync" in arms:
                w = closure_shared_write(cbody, recv, pset)
                if w is not None and not has_sync_guard(cbody + ftext):
                    kind, base, woff = w
                    rows.append(_row(
                        "shared_cell_unsync", filename, name,
                        _line_of(ftext, spawn_off, start_line),
                        f"goroutine writes captured shared cell "
                        f"'{base}' ({kind}) with no mutex/channel/atomic guard",
                        ingress))

        # (b) BLOCKING-OP: escape-less select.
        if "select_no_escape" in arms:
            for sel_off, sbody in iter_selects(ftext):
                if not select_is_escaped(sbody):
                    rows.append(_row(
                        "select_no_escape", filename, name,
                        _line_of(ftext, sel_off, start_line),
                        "select{} with no default / ctx.Done() / timer escape "
                        "(can deadlock or leak the goroutine)",
                        ingress))
    return rows


def _row(arm, filename, fn, line, point, ingress):
    return {
        "tool": TOOL,
        "capability": "R12-go-goroutine-lifecycle-safety-census",
        "arm": arm,
        "file": filename,
        "line": line,
        "function": fn,
        "enforcement_point": point,
        "private_invariant": _INVARIANT[arm],
        "ingress_adjacent": ingress,
        "attack_class": "go-goroutine-lifecycle-liveness",
        "exploit_class": _EXPLOIT[arm],
        "verdict": "needs-fuzz",
        "no_auto_credit": True,
        "confirm_lane": "go test -race / deadlock-repro over the ingress path",
    }


def analyze_file(path: pathlib.Path, all_scopes=False, arms=None):
    try:
        src = path.read_text(errors="replace")
    except Exception:
        return []
    return analyze_source(src, str(path), all_scopes=all_scopes, arms=arms)


def _iter_go_files(ws: pathlib.Path):
    for p in ws.rglob("*.go"):
        s = str(p)
        if p.name.endswith("_test.go"):
            continue
        if "/.auditooor/" in s.replace(os.sep, "/"):
            continue
        if "/vendor/" in s.replace(os.sep, "/"):
            continue
        if "/.engage_scratch/" in s.replace(os.sep, "/"):
            continue
        yield p


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--workspace")
    g.add_argument("--file")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--arm", action="append", choices=list(ARMS))
    ap.add_argument("--out", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rows = []
    files_scanned = 0
    if args.file:
        p = pathlib.Path(args.file)
        if not p.is_file():
            print(f"[err] file not found: {p}", file=sys.stderr)
            sys.exit(1)
        rows = analyze_file(p, all_scopes=args.all, arms=args.arm)
        files_scanned = 1
        out_default = None
    else:
        ws = pathlib.Path(args.workspace)
        if not ws.is_dir():
            print(f"[err] workspace not found: {ws}", file=sys.stderr)
            sys.exit(1)
        for p in _iter_go_files(ws):
            files_scanned += 1
            rows.extend(analyze_file(p, all_scopes=args.all, arms=args.arm))
        out_default = ws / OUT_REL

    per_arm = {a: sum(1 for r in rows if r["arm"] == a) for a in ARMS}
    acc = {
        "tool": TOOL,
        "capability": "R12-go-goroutine-lifecycle-safety-census",
        "status": "ok",
        "advisory_first": True,
        "files_scanned": files_scanned,
        "ingress_gate": (not args.all),
        "hypotheses": len(rows),
        "per_arm": per_arm,
    }

    out_path = pathlib.Path(args.out) if args.out else out_default
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        acc_path = out_path.parent / pathlib.Path(ACC_REL).name
        with open(acc_path, "w") as f:
            json.dump(acc, f, indent=2)

    if args.json:
        print(json.dumps({"accounting": acc, "hypotheses": rows}, indent=2))
    else:
        print(f"[ok] {TOOL}: files={files_scanned} "
              f"hypotheses(needs-fuzz)={len(rows)} per_arm={per_arm} "
              f"ingress_gate={not args.all}")

    # Advisory-first: NEVER fail-close.
    sys.exit(0)


if __name__ == "__main__":
    main()
