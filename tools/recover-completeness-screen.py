#!/usr/bin/env python3
"""recover-completeness-screen.py  (MQ-B06) - recover()-catchable-set completeness.

WHAT THIS TOOL IS
=================
A GENERAL, target-agnostic INVARIANT / TRUST-ENFORCEMENT screen for Go node
software. It is NOT a specific bug-shape detector. It enumerates a fixed class of
FAULT-CONTAINMENT ENFORCEMENT POINTS - functions that DELEGATE their liveness to
a `defer ... recover()` guard - and, for each, states the private invariant the
rest of the node TRUSTS that guard to discharge, then asks whether the guard is
actually COMPLETE. It applies the north-star method:

  "A TRUSTED ENFORCEMENT is bypassable or its private invariant is unsound."

THE DELEGATED-AND-TRUSTED INVARIANT (per the north-star)
-------------------------------------------------------
A Go node keeps itself alive on an untrusted-input path by wrapping the body in
`defer func(){ recover() }()`. The rest of the system DELEGATES process liveness
to that guard and TRUSTS it to contain any fault the body can raise. The guard's
PRIVATE INVARIANT is:

  "every fault reachable on this guarded body is a Go panic - a member of
   recover()'s catchable set."

recover() catches `panic(...)` and the panic-class runtime errors (nil deref,
index-out-of-range, divide-by-zero, type assertion). It does NOT catch the
`runtime.throw` / `fatalthrow` FATAL class. If a fault of that class is reachable
on the guarded body, the guard is INCOMPLETE: the fault escapes recover() and
halts the whole process (validator / RPC node / sequencer) DESPITE the guard -
the delegated liveness invariant is unsound.

THE RECOVER-PROOF (fatalthrow) FAULT CLASSES THIS SCREEN ENUMERATES
------------------------------------------------------------------
  (A) concurrent_map_fatal        - a shared map is read+written across
      goroutines with no synchronisation. Go's runtime raises
      `fatal error: concurrent map read and map write` via runtime.throw, which
      recover() CANNOT intercept (runtime/map.go throw / go.dev/ref/mem).

  (B) unbounded_recursion_fatal   - an attacker-driven self-recursion with no
      depth/limit bound overflows the goroutine stack:
      `runtime: goroutine stack exceeds ... limit` -> fatalthrow, uncatchable.

  (C) blocking_deadlock_fatal     - a bare blocking channel op / WaitGroup.Wait
      with no select / timeout / cancellation escape can deadlock every
      goroutine: `fatal error: all goroutines are asleep - deadlock!` ->
      fatalthrow, uncatchable.

Each is a genuine `runtime.throw` condition - NOT a recoverable panic - so a
recover()-guarded body containing a reachable instance of one is a FALSE SHIELD.

DISTINCT FROM THE MISSING-RECOVER CENSUS (why this is net-new)
-------------------------------------------------------------
go-goroutine-lifecycle-census (R12/G12) flags a body that has NO recover. This
screen is the DUAL: it flags a body that HAS a recover and is trusted BECAUSE of
it, yet whose catchable-set does not cover a reachable fatal. The presence of the
guard is precisely what makes the residual fatal dangerous - operators read the
guard as "this path cannot halt the node" and it can.

GENERALITY (this is a class, not a shape)
-----------------------------------------
The recover-guarded-body enforcement set and the fatalthrow fault taxonomy are
fixed and target-independent, instantiated per target from whatever Go source is
in scope. It never encodes a specific vulnerable function, protocol, or impact
string.

ADVISORY-FIRST / NO-AUTO-CREDIT (hard contract)
-----------------------------------------------
Every emitted row carries verdict="needs-fuzz", no_auto_credit=true,
auto_credit=false. This tool NEVER flips a gate, NEVER resolves a unit, and NEVER
fail-closes: it always exits 0. Static reachability of a fatalthrow is a
HYPOTHESIS; a `go test -race` (concurrent map), a deep-recursion repro (stack), or
a deadlock repro is the confirmation lane.

Usage:
  python3 tools/recover-completeness-screen.py --workspace <ws> [--json]
  python3 tools/recover-completeness-screen.py --file <a.go> [--all] [--json]
  python3 tools/recover-completeness-screen.py --file <a.go> --arm concurrent_map_fatal

Flags:
  --workspace DIR  scan every *.go (non _test.go) under DIR; emit sidecar.
  --file FILE      scan a single Go file (tests / fleet-FP spot checks).
  --all            do NOT require concurrency/ingress adjacency for arm A.
  --arm NAME       restrict to one arm (repeatable): concurrent_map_fatal |
                   unbounded_recursion_fatal | blocking_deadlock_fatal.
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

TOOL = "recover-completeness-screen"
CAP = "MQ-B06-recover-completeness"
OUT_REL = os.path.join(".auditooor", "recover_completeness_hypotheses.jsonl")
ACC_REL = os.path.join(".auditooor", "recover_completeness_accounting.json")

ARMS = ("concurrent_map_fatal", "unbounded_recursion_fatal",
        "blocking_deadlock_fatal")

# advisory env for optional future gate wiring; default OFF (evaluate() -> None).
_ADVISORY_ENV = "AUDITOOOR_RECOVER_COMPLETENESS_ADVISORY"


# --------------------------------------------------------------------------- #
# Comment / string stripping (length-preserving so byte offsets still map to   #
# original line numbers).                                                      #
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
# Top-level function splitting (gofmt: decl at column 0, close `}` at col 0).   #
# --------------------------------------------------------------------------- #
_FUNC_NAME = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z0-9_]+)")
_RECV = re.compile(r"^func\s*\(\s*([A-Za-z_]\w*)\s")


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


def _line_of(ftext: str, offset: int, fn_start_line: int) -> int:
    return fn_start_line + ftext[:offset].count("\n")


# --------------------------------------------------------------------------- #
# recover-guard predicate (the delegated enforcement point).                   #
# --------------------------------------------------------------------------- #
def recover_guarded(ftext: str) -> bool:
    """CORE PREDICATE. True iff the function delegates its liveness to a
    `defer ... recover()` guard: it contains both a `recover(` call and a
    `defer` (recover is a no-op outside a deferred frame, so this is the
    fault-containment idiom the node trusts to keep the process alive)."""
    if "recover(" not in ftext.replace(" ", ""):
        return False
    return re.search(r"\bdefer\b", ftext) is not None


# --------------------------------------------------------------------------- #
# Map-typedness ledger (file scope). Two disjoint sets so a shared map is       #
# distinguished from a fn-local one (a fn-local map is single-goroutine-owned   #
# and NOT a concurrent-access hazard):                                          #
#   * field_map_names  - names declared as `NAME map[..]` (struct fields + var  #
#     decls); used ONLY to confirm a DOTTED access `a.NAME[..]` is a map field  #
#     of a (shared) receiver/struct.                                            #
#   * global_map_names - package-level (column-0) map vars; a bare single-id    #
#     map is shared ONLY if it is one of these AND not fn-local-shadowed.       #
# --------------------------------------------------------------------------- #
_FIELD_MAP_RE = re.compile(r"\b([A-Za-z_]\w*)\s+map\[")
_GLOBAL_MAP_RES = (
    re.compile(r"^var\s+([A-Za-z_]\w*)\s+map\[", re.MULTILINE),
    re.compile(r"^var\s+([A-Za-z_]\w*)\s*=\s*map\[", re.MULTILINE),
    re.compile(r"^var\s+([A-Za-z_]\w*)\s*=\s*make\(map\[", re.MULTILINE),
    re.compile(r"^([A-Za-z_]\w*)\s*=\s*map\[", re.MULTILINE),
)


def field_map_names(file_stripped: str) -> set:
    return {m.group(1) for m in _FIELD_MAP_RE.finditer(file_stripped)}


def global_map_names(file_stripped: str) -> set:
    names = set()
    for rx in _GLOBAL_MAP_RES:
        for m in rx.finditer(file_stripped):
            names.add(m.group(1))
    return names


# --------------------------------------------------------------------------- #
# Arm (A): concurrent map mutation with no sync guard (concurrent_map_fatal).   #
# --------------------------------------------------------------------------- #
# An index-write LHS path: `a.filters[k] =` or `m[k] =` (captures the dotted    #
# path so the final segment can be checked against the map ledger).            #
_INDEX_WRITE = re.compile(
    r"(?P<path>[A-Za-z_]\w*(?:\.\w+)*)\s*\[[^\]\[]*\]\s*=(?!=)")
# `delete(m, k)` - delete is a MAP-ONLY builtin, so it self-confirms map-ness.
_DELETE = re.compile(r"\bdelete\(\s*(?P<path>[A-Za-z_]\w*(?:\.\w+)*)\s*,")
# synchronisation primitives that discharge the concurrent-access invariant.
_SYNC_GUARD = re.compile(
    r"\.\s*R?Lock\s*\(|\.\s*R?Unlock\s*\("
    r"|\batomic\s*\.\s*(?:Store|Load|Add|Swap|CompareAndSwap)\w*\s*\("
    r"|\bsync\.\s*Map\b")
_GO_SPAWN = re.compile(r"\bgo\s+(?:func\b|[A-Za-z_])")


def _last_segment(path: str) -> str:
    return path.split(".")[-1]


def concurrent_map_mutations(ftext, recv, fmaps, gmaps):
    """Yield (offset, path, kind) for each SHARED map mutation (index-write to a
    map-typed field/global, or a delete on one) - excluding fn-local maps, which
    are single-goroutine-owned and not a concurrency hazard."""
    hits = []
    for m in _DELETE.finditer(ftext):
        path = m.group("path")
        if _shared_map_cell(path, recv, fmaps, gmaps, ftext, self_confirms=True):
            hits.append((m.start(), path, "delete"))
    for m in _INDEX_WRITE.finditer(ftext):
        path = m.group("path")
        if _shared_map_cell(path, recv, fmaps, gmaps, ftext, self_confirms=False):
            hits.append((m.start(), path, "index_write"))
    hits.sort()
    return hits


def _shared_map_cell(path, recv, fmaps, gmaps, ftext, self_confirms) -> bool:
    """True iff `path` names a SHARED map cell (receiver/struct field or a
    package-global map), NOT a fn-local map. `delete` self-confirms map-ness."""
    seg = _last_segment(path)
    base = path.split(".")[0]
    if "." in path:
        # field access through a struct/receiver = shared long-lived state.
        return self_confirms or seg in fmaps
    # single identifier: shared only if a package-global map, not fn-local.
    if base not in gmaps:
        return False
    if re.search(r"\b" + re.escape(base) + r"\s*:=", ftext):  # local shadow.
        return False
    return True


def has_sync_guard(ftext: str) -> bool:
    return _SYNC_GUARD.search(ftext) is not None


def is_receiver_map_write(path: str, recv) -> bool:
    return recv is not None and path.split(".")[0] == recv and "." in path


# --------------------------------------------------------------------------- #
# Arm (B): unbounded self-recursion with no depth bound.                       #
# --------------------------------------------------------------------------- #
# tokens that evidence a recursion depth / size bound was enforced.
_DEPTH_GUARD = re.compile(
    r"\bdepth\b|\bmaxdepth\b|\brecursion\b|\brecurse\b|\bmaxrecursion\b"
    r"|\bremaining\b|\bbudget\b|\bmaxdeep\b|\bnesting\b|\bstack(?:limit|depth)\b"
    r"|\blimit\b|\bmaxlen\b|\bmaxsize\b", re.IGNORECASE)


def self_recursion_offset(name: str, ftext: str, recv):
    """Return the offset of the FIRST genuine SYNCHRONOUS self-call inside the
    body (after the declaration), or None. A genuine self-call is either a bare
    package-fn call `name(` or a method call on THIS receiver `recv.name(` - NOT
    a call to a same-named method on a DIFFERENT object (`x.other.name(` is
    delegation, not recursion). A leading non-dot/non-word look-behind anchors
    the selector chain so a dotted base preceded by another dot (a different
    object) never matches.

    A candidate whose immediately-preceding non-space token is `go` or `defer`
    is REJECTED: `go self(...)` schedules the call on a FRESH goroutine stack
    and `defer self(...)` runs it after the frame unwinds - both are a RESTART,
    not synchronous stack-consuming recursion, so neither can overflow the stack
    the way an in-line self-call does (arm C already excludes _GO_SPAWN; arm B
    must too, or a goroutine-restart-on-recover idiom reads as a false fatal)."""
    if not name or name == "?":
        return None
    bopen = ftext.find("{")  # skip the declaration itself.
    if bopen < 0:
        return None
    body = ftext[bopen:]
    pat = re.compile(
        r"(?<![.\w])(?:(?P<base>[A-Za-z_]\w*)\s*\.\s*)?"
        + re.escape(name) + r"\s*\(")
    for m in pat.finditer(body):
        # Reject a goroutine-spawned / deferred self-call: the preceding
        # non-space token being `go`/`defer` makes it a restart, not recursion.
        pre_tok = re.search(r"([A-Za-z_]\w*)\s*$", body[:m.start()])
        if pre_tok is not None and pre_tok.group(1) in ("go", "defer"):
            continue
        base = m.group("base")
        if base is None:            # bare package-function self-call.
            return bopen + m.start()
        if recv is not None and base == recv:  # method call on THIS receiver.
            return bopen + m.start()
    return None


def has_depth_bound(ftext: str) -> bool:
    return _DEPTH_GUARD.search(ftext) is not None


# --------------------------------------------------------------------------- #
# Arm (C): bare blocking channel op / WaitGroup.Wait with no escape.           #
# --------------------------------------------------------------------------- #
_SELECT = re.compile(r"\bselect\s*\{")
_TIMEOUT_ESC = re.compile(
    r"time\.After\s*\(|time\.Tick\w*\s*\(|\.Done\s*\(\s*\)|context\.")
# a statement-form bare receive `<-ch` (line, after strip, starts with `<-`).
_BARE_RECV_LINE = re.compile(r"^<-\s*[A-Za-z_][\w.]*\s*$")
_WAIT_CALL = re.compile(r"\b[A-Za-z_]\w*\s*\.\s*Wait\s*\(\s*\)")


def blocking_deadlock_offset(ftext: str):
    """Return (offset, kind) of a bare blocking op with no select / timeout /
    cancellation escape and no goroutine spawn to feed or drain it, else None.
    Such an op can raise `fatal error: all goroutines are asleep - deadlock!`,
    a fatalthrow recover() cannot catch."""
    if _SELECT.search(ftext) or _TIMEOUT_ESC.search(ftext):
        return None
    if _GO_SPAWN.search(ftext):
        return None
    # bare statement-form receive.
    off = 0
    for line in ftext.split("\n"):
        s = line.strip()
        if _BARE_RECV_LINE.match(s):
            return off + (line.find("<-")), "bare_recv"
        off += len(line) + 1
    m = _WAIT_CALL.search(ftext)
    if m is not None:
        return m.start(), "waitgroup_wait"
    return None


# --------------------------------------------------------------------------- #
# Concurrency / ingress adjacency (justifies the "concurrent" in arm A + the    #
# attacker-driven ingress in arm B).                                           #
# --------------------------------------------------------------------------- #
_INGRESS_TEXT = re.compile(
    r"\bCheckTx\b|\bDeliverTx\b|\bRecheckTx\b|\bServeHTTP\b|\bServeMsg"
    r"|MsgServer|msgServer|\bRegisterService\b|\bReceive(?:Envelope)?\s*\("
    r"|\bReactor\b|\bmempool\b|\bMempool\b|\bp2p\b|\bgrpc\b|\bhttp\."
    r"|\babci\.|BeginBlock|EndBlock|PreBlock|RunMsg|ProcessProposal"
    r"|PrepareProposal|ExtendVote|VerifyVoteExtension|\bHandle[A-Z]\w*\s*\("
    r"|\bnewFilter\b|\bnewHeads\b|\bSubscri|\bQuery[A-Z]\w*\s*\(|\bServeQuery\b"
    r"|Unmarshal|Decode|\bParse[A-Z]\w*\s*\(")
_INGRESS_PATH = re.compile(
    r"(?:^|/)(?:rpc|evmrpc|p2p|mempool|abci|server|handler|handlers|api|"
    r"msgserver|grpc|filter|subscribe)(?:/|_|\.go$)", re.IGNORECASE)


def is_ingress_adjacent(ftext: str, filename: str) -> bool:
    if _INGRESS_TEXT.search(ftext):
        return True
    return _INGRESS_PATH.search(filename.replace(os.sep, "/")) is not None


# --------------------------------------------------------------------------- #
# Per-arm metadata.                                                            #
# --------------------------------------------------------------------------- #
_FATAL = {
    "concurrent_map_fatal": "concurrent map read and map write (runtime.throw)",
    "unbounded_recursion_fatal":
        "goroutine stack exceeds limit / stack overflow (fatalthrow)",
    "blocking_deadlock_fatal":
        "all goroutines are asleep - deadlock! (fatalthrow)",
}
_INVARIANT = {
    "concurrent_map_fatal":
        "every fault on this recover-guarded body is a recover-catchable panic; "
        "a concurrent map read+write is a runtime.throw fatal recover() cannot "
        "intercept, so the map must be synchronised (mutex / atomic / sync.Map)",
    "unbounded_recursion_fatal":
        "every fault on this recover-guarded body is a recover-catchable panic; "
        "attacker-driven unbounded recursion overflows the stack (fatalthrow, "
        "uncatchable), so recursion depth must be bounded",
    "blocking_deadlock_fatal":
        "every fault on this recover-guarded body is a recover-catchable panic; "
        "a blocking op with no escape can deadlock all goroutines (fatalthrow, "
        "uncatchable), so the wait must have a select / timeout / cancellation",
}
_CONFIRM = {
    "concurrent_map_fatal":
        "go test -race over the ingress path exercising concurrent map access",
    "unbounded_recursion_fatal":
        "deep-nesting input repro driving the recursion past the stack limit",
    "blocking_deadlock_fatal":
        "deadlock repro (no sender/closer) hitting the all-goroutines-asleep throw",
}


def _row(arm, filename, fn, line, point, ingress):
    return {
        "tool": TOOL,
        "capability": CAP,
        "arm": arm,
        "file": filename,
        "line": line,
        "function": fn,
        "enforcement_point": point,
        "private_invariant": _INVARIANT[arm],
        "recover_guarded": True,
        "recover_proof_fatal": _FATAL[arm],
        "ingress_adjacent": ingress,
        "attack_class": "runtime-fault-containment-completeness",
        "exploit_class": "node-halt-despite-recover-guard",
        "verdict": "needs-fuzz",
        "no_auto_credit": True,
        "auto_credit": False,
        "confirm_lane": _CONFIRM[arm],
    }


# --------------------------------------------------------------------------- #
# Analysis                                                                      #
# --------------------------------------------------------------------------- #
def analyze_source(src: str, filename: str, all_scopes: bool = False,
                   arms=None):
    """Return the list of hypothesis rows for one Go source string."""
    arms = set(arms) if arms else set(ARMS)
    stripped = strip_comments_strings(src)
    fmaps = field_map_names(stripped)
    gmaps = global_map_names(stripped)
    rows = []
    for name, start_line, ftext in split_top_functions(stripped):
        # THE delegated enforcement point: a recover-guarded body.
        if not recover_guarded(ftext):
            continue
        recv_m = _RECV.match(ftext)
        recv = recv_m.group(1) if recv_m else None
        ingress = is_ingress_adjacent(ftext, filename)

        # (A) concurrent map fatal.
        if "concurrent_map_fatal" in arms and not has_sync_guard(ftext):
            for off, path, kind in concurrent_map_mutations(ftext, recv, fmaps, gmaps):
                concurrent = (is_receiver_map_write(path, recv)
                              or _GO_SPAWN.search(ftext) is not None
                              or ingress)
                if not all_scopes and not concurrent:
                    continue
                rows.append(_row(
                    "concurrent_map_fatal", filename, name,
                    _line_of(ftext, off, start_line),
                    f"recover-guarded body mutates shared map '{path}' ({kind}) "
                    f"with no mutex/atomic/sync.Map guard",
                    ingress))
                break  # one row per guarded body is enough (same fatal class).

        # (B) unbounded recursion fatal.
        if "unbounded_recursion_fatal" in arms and not has_depth_bound(ftext):
            off = self_recursion_offset(name, ftext, recv)
            if off is not None and (all_scopes or ingress):
                rows.append(_row(
                    "unbounded_recursion_fatal", filename, name,
                    _line_of(ftext, off, start_line),
                    f"recover-guarded body self-recurses ('{name}') with no "
                    f"depth/limit bound (attacker-driven stack overflow)",
                    ingress))

        # (C) blocking deadlock fatal.
        if "blocking_deadlock_fatal" in arms:
            res = blocking_deadlock_offset(ftext)
            if res is not None:
                off, kind = res
                rows.append(_row(
                    "blocking_deadlock_fatal", filename, name,
                    _line_of(ftext, off, start_line),
                    f"recover-guarded body blocks ({kind}) with no "
                    f"select/timeout/cancellation escape",
                    ingress))
    return rows


def analyze_file(path: pathlib.Path, all_scopes=False, arms=None):
    try:
        src = path.read_text(errors="replace")
    except Exception:
        return []
    return analyze_source(src, str(path), all_scopes=all_scopes, arms=arms)


def _iter_go_files(ws: pathlib.Path):
    for p in ws.rglob("*.go"):
        s = str(p).replace(os.sep, "/")
        if p.name.endswith("_test.go"):
            continue
        if "/.auditooor/" in s or "/vendor/" in s or "/.engage_scratch/" in s:
            continue
        yield p


# --------------------------------------------------------------------------- #
# Public API (produce_hypotheses / evaluate / run) for tests + future wiring.  #
# --------------------------------------------------------------------------- #
def produce_hypotheses(ws, all_scopes=False, arms=None):
    ws = pathlib.Path(ws)
    rows = []
    for p in _iter_go_files(ws):
        rows.extend(analyze_file(p, all_scopes=all_scopes, arms=arms))
    return rows


def run(ws, out=None, all_scopes=False, arms=None):
    """Always-emit sidecar (advisory-first). Returns the output Path."""
    ws = pathlib.Path(ws)
    rows = produce_hypotheses(ws, all_scopes=all_scopes, arms=arms)
    out_path = pathlib.Path(out) if out else ws / OUT_REL
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return out_path


def evaluate(ws):
    """Optional gate-style summary. Advisory OFF by default (returns dict with
    the summary under the tool key = None) unless the advisory env is set."""
    if os.environ.get(_ADVISORY_ENV) not in ("1", "true", "True"):
        return {TOOL.replace("-", "_"): None}
    rows = produce_hypotheses(ws)
    run(ws)
    return {TOOL.replace("-", "_"): {
        "enabled": True,
        "verdict": "needs-fuzz",
        "count": len(rows),
        "auto_credit": False,
    }}


def _accounting(rows, files_scanned, ingress_gate):
    per_arm = {a: sum(1 for r in rows if r["arm"] == a) for a in ARMS}
    return {
        "tool": TOOL,
        "capability": CAP,
        "status": "ok",
        "advisory_first": True,
        "auto_credit": False,
        "files_scanned": files_scanned,
        "concurrency_gate": ingress_gate,
        "hypotheses": len(rows),
        "per_arm": per_arm,
    }


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
    out_default = None
    if args.file:
        p = pathlib.Path(args.file)
        if not p.is_file():
            print(f"[err] file not found: {p}", file=sys.stderr)
            sys.exit(1)
        rows = analyze_file(p, all_scopes=args.all, arms=args.arm)
        files_scanned = 1
    else:
        ws = pathlib.Path(args.workspace)
        if not ws.is_dir():
            print(f"[err] workspace not found: {ws}", file=sys.stderr)
            sys.exit(1)
        for p in _iter_go_files(ws):
            files_scanned += 1
            rows.extend(analyze_file(p, all_scopes=args.all, arms=args.arm))
        out_default = ws / OUT_REL

    acc = _accounting(rows, files_scanned, not args.all)

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
              f"hypotheses(needs-fuzz)={len(rows)} per_arm={acc['per_arm']} "
              f"concurrency_gate={not args.all}")

    # Advisory-first: NEVER fail-close.
    sys.exit(0)


if __name__ == "__main__":
    main()
