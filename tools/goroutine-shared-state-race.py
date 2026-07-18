#!/usr/bin/env python3
"""goroutine-shared-state-race.py - the CONCURRENT SHARED-MUTABLE-STATE-WITHOUT-SYNC
reasoner (RANK-9 [HIGH x11]).

GENERAL LOGIC class, never a bug SHAPE. It is a LOCK-SET DIFFERENCE over
goroutine-partitioned accesses - NOT a grep for `go ` or `map`.

REASONING QUERY
  For each shared mutable field S (a package-level var, a struct field on a shared
  receiver, or a map/slice/chan), collect
      ACCESS(S) = { (fn, kind) : fn reads or writes S }.
  Partition ACCESS(S) by goroutine-reachability: a fn is in a goroutine context if it
  is the target of a `go` statement, is the body of a `go func(){...}` closure, or is a
  concurrent entrypoint (ServeHTTP / gRPC handler / (Begin|End)Block(er) / Run / Start /
  Serve / Listen / watch / poll / worker / loop / subscribe).
  Compute the HELD-LOCK-SET L(a) for each access a = the set of mutexes locked (`.Lock()`
  / `.RLock()` with a matching Unlock, or `defer x.Unlock()`) that dominate the access.
      SURVIVOR = S with >= 2 accesses in DISTINCT goroutine contexts where
          intersection over those accesses of L(a) is EMPTY
      (no single mutex is held on EVERY concurrent access of S).

  SURVIVORS = SHARED_MULTIGOROUTINE_FIELDS \\ COMMON_LOCK_PROTECTED.

A survivor is a data race / concurrent-map-write. A concurrent map write is a Go runtime
`fatal error: concurrent map writes` = an unrecoverable process crash = a chain / node
halt (HIGH).

GUARD-RAIL: this is a lock-set intersection over goroutine-partitioned accesses. Fields
that ARE protected by a common mutex on every concurrent access are DROPPED. Fields that
are goroutine-local (only one context) are DROPPED. The difference is what survives.

ADVISORY-FIRST: goroutine-reachability and the held-lock-set are computed lexically and are
APPROXIMATE, so every survivor row carries advisory=True, auto_credit=False,
verdict='needs-source' and needs_source=True. --fail-closed only elevates the exit code.

Usage:
  --workspace <ws>     scan <ws>/src (or <ws>) -> sidecar + summary; bare name resolves
                       under /Users/wolf/audits/<name>
  --src-root <dir>     scan an arbitrary dir (test / ad-hoc)
  --emit               write the sidecar jsonl under <ws>/.auditooor/
  --json               machine summary to stdout
  --check              re-read the emitted sidecar, print cert verdict (advisory)
  --fail-closed        elevate exit code when a survivor exists (also env
                       AUDITOOOR_GOROUTINE_RACE_STRICT)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.goroutine_shared_state_race.v1"
_SIDE_NAME = "goroutine_shared_state_race_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_GOROUTINE_RACE_STRICT"

_SKIP_DIRS = {".git", "vendor", "node_modules", "_archive", "out", "cache",
              "__pycache__", "dist", "build", ".auditooor", "testdata"}
# generated Go (never the CUT); a race there is not attacker-drivable production code
_GEN_HINT = re.compile(r"\.(pb|pulsar)\.go$|_test\.go$|(^|/)mock(s)?/")
_GEN_HEADER = re.compile(r"^//\s*Code generated .* DO NOT EDIT", re.M)

# --- lexical primitives (Go) ------------------------------------------------
# a struct decl:  type Name struct {
_STRUCT_RE = re.compile(r"^\s*type\s+([A-Za-z_]\w*)\s+struct\s*\{")
# a func / method:  func (v *T) Name(  |  func Name(
_FUNC_RE = re.compile(
    r"^\s*func\s*(?:\(\s*([A-Za-z_]\w*)\s+\*?([A-Za-z_]\w*)\s*\)\s*)?([A-Za-z_]\w*)\s*\(")
# a package-level var:  var name  |  var ( ... )
_VAR_LINE_RE = re.compile(r"^\s*var\s+([A-Za-z_]\w*)\b")
_VAR_BLOCK_RE = re.compile(r"^\s*var\s*\($")
_VAR_IN_BLOCK_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s")
# a go statement:  go foo(  |  go v.M(  |  go func(
_GO_NAMED_RE = re.compile(r"\bgo\s+(?:[A-Za-z_]\w*\.)?([A-Za-z_]\w*)\s*\(")
_GO_CLOSURE_RE = re.compile(r"\bgo\s+func\s*\(")
# lock acquire / release
_LOCK_RE = re.compile(r"\b([A-Za-z_][\w.]*)\.(?:R)?Lock\s*\(\s*\)")
_UNLOCK_RE = re.compile(r"\b([A-Za-z_][\w.]*)\.(?:R)?Unlock\s*\(\s*\)")
# mutex field type
_MUTEX_TYPE_RE = re.compile(r"\b(?:sync\.)?(?:RW)?Mutex\b")

# concurrent entrypoint fn names (goroutine-equivalent contexts)
_ENTRY_RE = re.compile(
    r"^(ServeHTTP|EndBlock(er)?|BeginBlock(er)?|Run|Start|Serve|Listen|"
    r"[Ww]atch|[Pp]oll|[Ww]orker|[Ll]oop|[Ss]ubscribe|[Hh]andle\w*|[Pp]rocess\w*)$")

_MUT_METHODS = ("push", "pop", "insert", "remove", "set", "clear", "take", "delete",
                "add", "store", "reset", "append", "put", "inc", "dec")


def _iter_go_files(root: Path):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in _SKIP_DIRS]
        for fn in fns:
            if not fn.endswith(".go"):
                continue
            p = Path(dp) / fn
            rel = str(p)
            if _GEN_HINT.search(rel.replace(str(root), "")):
                continue
            yield p


def _strip_lock_token(tok: str) -> str:
    """normalize a lock expr to a receiver-independent token.

    c.lock -> lock ;  mu -> mu ;  s.mu.inner -> inner (trailing ident).
    This lets two methods on the SAME receiver type that lock the same field be
    recognized as holding the SAME lock even though the receiver var names differ.
    """
    return tok.split(".")[-1]


def _brace_body(lines, start_idx):
    """return (body_text, end_idx) for the block opened on/after start_idx."""
    depth = 0
    seen = False
    out = []
    i = start_idx
    while i < len(lines):
        ln = lines[i]
        out.append(ln)
        depth += ln.count("{") - ln.count("}")
        if "{" in ln:
            seen = True
        if seen and depth <= 0:
            return "\n".join(out), i
        i += 1
    return "\n".join(out), len(lines) - 1


def _parse_structs(lines):
    """map struct-type-name -> {field: {'mutable':bool,'mutex':bool}}."""
    structs = {}
    i = 0
    while i < len(lines):
        m = _STRUCT_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        body, end = _brace_body(lines, i)
        fields = {}
        for bl in body.split("\n")[1:]:
            bl_s = bl.strip()
            if not bl_s or bl_s.startswith("//") or bl_s == "}":
                continue
            fm = re.match(r"^([A-Za-z_]\w*)\s+(.+)$", bl_s)
            if not fm:
                continue
            fname, ftype = fm.group(1), fm.group(2)
            is_mutex = bool(_MUTEX_TYPE_RE.search(ftype))
            # mutable candidate: map / slice / chan / pointer / scalar (anything but a mutex)
            fields[fname] = {"mutex": is_mutex, "type": ftype}
        structs[name] = fields
        i = end + 1
    return structs


def _parse_pkg_vars(lines):
    """collect package-level (top-level indentation) var names."""
    vars_ = set()
    i = 0
    in_block = False
    while i < len(lines):
        ln = lines[i]
        # only column-0 declarations are package level
        if _VAR_BLOCK_RE.match(ln):
            in_block = True
            i += 1
            continue
        if in_block:
            if ln.strip() == ")":
                in_block = False
            else:
                vm = _VAR_IN_BLOCK_RE.match(ln)
                if vm and vm.group(1) != "_" and not ln.startswith("\t\t"):
                    vars_.add(vm.group(1))
            i += 1
            continue
        m = _VAR_LINE_RE.match(ln)
        if m and m.group(1) != "_" and (ln.startswith("var ")):
            vars_.add(m.group(1))
        i += 1
    return vars_


def _held_locks(body: str) -> set:
    """set of normalized lock tokens held over the body (Lock w/ matching Unlock)."""
    acquired = {_strip_lock_token(t) for t in _LOCK_RE.findall(body)}
    released = {_strip_lock_token(t) for t in _UNLOCK_RE.findall(body)}
    # a lock is "held over accesses" only if it is both acquired and released
    # (defer Unlock counts: _UNLOCK_RE matches `defer c.mu.Unlock()`)
    return acquired & released


def _accesses_in_body(body, recv_var, recv_type, structs, pkg_vars):
    """return list of (target, kind) where target = ('field',type,name) or ('var',name)."""
    out = []
    fields = structs.get(recv_type, {}) if recv_type else {}
    if recv_var and fields:
        for fname, meta in fields.items():
            if meta["mutex"]:
                continue
            # write: recv.field =  |  recv.field[..] =  |  recv.field.<mut>(  | append(recv.field
            wr = re.compile(
                r"\b" + re.escape(recv_var) + r"\." + re.escape(fname) +
                r"(?:\s*\[[^\]]*\]\s*)?\s*(?:[-+*/]?=(?![=])|\s*\.\s*(?:" +
                "|".join(_MUT_METHODS) + r")\s*\()")
            append_wr = re.compile(
                r"\bappend\s*\(\s*" + re.escape(recv_var) + r"\." + re.escape(fname) + r"\b")
            rd = re.compile(r"\b" + re.escape(recv_var) + r"\." + re.escape(fname) + r"\b")
            if wr.search(body) or append_wr.search(body):
                out.append((("field", recv_type, fname), "write"))
            elif rd.search(body):
                out.append((("field", recv_type, fname), "read"))
    for vn in pkg_vars:
        wr = re.compile(r"\b" + re.escape(vn) +
                        r"(?:\s*\[[^\]]*\]\s*)?\s*(?:[-+*/]?=(?![=])|\s*\.\s*(?:" +
                        "|".join(_MUT_METHODS) + r")\s*\()")
        append_wr = re.compile(r"\bappend\s*\(\s*" + re.escape(vn) + r"\b")
        rd = re.compile(r"\b" + re.escape(vn) + r"\b")
        if wr.search(body) or append_wr.search(body):
            out.append((("var", None, vn), "write"))
        elif rd.search(body):
            out.append((("var", None, vn), "read"))
    return out


def scan_file(path: Path, rel: str):
    """return (functions, go_targets, structs, pkg_vars) parsed from one file."""
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return [], set(), {}, set()
    if _GEN_HEADER.search(text[:400]):
        return [], set(), {}, set()
    lines = text.split("\n")
    structs = _parse_structs(lines)
    pkg_vars = _parse_pkg_vars(lines)
    go_named = set(_GO_NAMED_RE.findall(text))

    funcs = []
    i = 0
    while i < len(lines):
        m = _FUNC_RE.match(lines[i])
        if not m:
            i += 1
            continue
        recv_var, recv_type, name = m.group(1), m.group(2), m.group(3)
        body, end = _brace_body(lines, i)
        # closures launched via `go func(){...}` inside this fn -> extra goroutine ctx
        has_go_closure = bool(_GO_CLOSURE_RE.search(body))
        funcs.append({
            "file": rel, "name": name, "recv_var": recv_var, "recv_type": recv_type,
            "line": i + 1, "body": body, "held_locks": _held_locks(body),
            "accesses": _accesses_in_body(body, recv_var, recv_type, structs, pkg_vars),
            "has_go_closure": has_go_closure,
        })
        i = end + 1
    return funcs, go_named, structs, pkg_vars


def _is_goroutine_ctx(fn, go_targets):
    if fn["name"] in go_targets:
        return True
    if _ENTRY_RE.match(fn["name"]):
        return True
    return False


def analyze(root: Path):
    all_funcs = []
    all_go = set()
    for p in _iter_go_files(root):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        funcs, go_named, _s, _v = scan_file(p, rel)
        all_funcs.extend(funcs)
        all_go |= go_named

    # ACCESS(S): field targets keyed by (type,name); var targets by name
    access = {}   # key -> list of {fn, kind, gctx, locks}
    shared_fields = set()
    for fn in all_funcs:
        gctx = _is_goroutine_ctx(fn, all_go) or fn["has_go_closure"]
        for target, kind in fn["accesses"]:
            shared_fields.add(target)
            access.setdefault(target, []).append({
                "fn": fn["name"], "file": fn["file"], "line": fn["line"],
                "kind": kind, "gctx": bool(gctx), "locks": fn["held_locks"],
            })

    n_shared = len(shared_fields)
    multi = {}
    for key, accs in access.items():
        gacc = [a for a in accs if a["gctx"]]
        gctxs = {(a["fn"], a["file"]) for a in gacc}
        # multi-goroutine: >=2 distinct goroutine-context fns touch S, and >=1 is a write
        if len(gctxs) >= 2 and any(a["kind"] == "write" for a in gacc):
            multi[key] = gacc
    n_multi = len(multi)

    survivors = []
    n_protected = 0
    for key, gacc in multi.items():
        lock_sets = [a["locks"] for a in gacc]
        common = set.intersection(*lock_sets) if lock_sets else set()
        if common:
            n_protected += 1
            continue
        kind, typ, name = key
        contexts = [{"fn": a["fn"], "file": a["file"], "line": a["line"],
                     "kind": a["kind"], "locks": sorted(a["locks"])} for a in gacc]
        sid = hashlib.sha1(
            f"{kind}:{typ}:{name}:{sorted((c['fn'], c['file']) for c in contexts)}"
            .encode()).hexdigest()[:12]
        survivors.append({
            "schema": SCHEMA, "id": sid,
            "shared_state": {"kind": kind, "type": typ, "name": name},
            "goroutine_contexts": sorted(contexts, key=lambda c: (c["file"], c["line"])),
            "common_lock_set": [],
            "verdict": "needs-source", "advisory": True, "auto_credit": False,
            "needs_source": True,
            "question": (
                f"shared {kind} `{(typ + '.') if typ else ''}{name}` is written/read from "
                f">= 2 distinct goroutine contexts "
                f"({', '.join(sorted({c['fn'] for c in contexts}))}) with NO common mutex "
                f"held on every access -> data race / concurrent-map-write (Go fatal = halt). "
                f"Confirm the contexts run concurrently and no external lock dominates."),
        })
    survivors.sort(key=lambda r: r["id"])
    return {
        "n_shared": n_shared, "n_multi": n_multi,
        "n_protected": n_protected, "survivors": survivors,
    }


def _summary(res, substrate_status):
    return {
        "schema": SCHEMA,
        "shared_fields": res["n_shared"],
        "multi_goroutine": res["n_multi"],
        "common_lock_protected": res["n_protected"],
        "survivors": len(res["survivors"]),
        "kept": [s["id"] for s in res["survivors"]],
        "substrate": substrate_status,
        "verdict": "needs-source" if res["survivors"] else (
            "cited-empty" if substrate_status == "substrate_present" else "substrate_vacuous"),
        "advisory": True, "auto_credit": False,
    }


def _emit_sidecar(ws: Path, survivors):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        if survivors:
            for r in survivors:
                fh.write(json.dumps(r) + "\n")
        else:
            # cited-empty proof-of-run marker (query ran, 0 survivors) so the
            # step verifier's file_exists passes on a clean run without a 0-byte file.
            fh.write(json.dumps({"schema": SCHEMA, "survivors": 0,
                                 "note": "cited-empty: lock-set-difference goroutine race "
                                         "screen ran, no shared-mutable-state race survivor"}) + "\n")
    return out


def _resolve_ws(name):
    ws = Path(name)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / name
        if cand.exists():
            return cand
    return ws


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="goroutine shared-mutable-state race reasoner (lock-set difference)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--src-root")
    ap.add_argument("--emit", action="store_true", help="(default-on) write the sidecar")
    ap.add_argument("--no-emit", action="store_true", help="suppress writing the sidecar")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--fail-closed", action="store_true")
    args = ap.parse_args(argv)

    strict = args.fail_closed or os.environ.get(_STRICT_ENV, "").strip() not in ("", "0", "false")

    if args.src_root:
        root = Path(args.src_root)
        res = analyze(root)
        # a src-root scan is a raw substrate; presence = any Go file seen -> shared>0 or files
        substrate = "substrate_present" if any(root.rglob("*.go")) else "substrate_vacuous"
        summ = _summary(res, substrate)
        print(json.dumps({"summary": summ, "survivors": res["survivors"]}, indent=2))
        return 1 if (strict and res["survivors"]) else 0

    if not args.workspace:
        ap.error("one of --workspace / --src-root is required")
    ws = _resolve_ws(args.workspace)
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
        summ = {"schema": SCHEMA, "source": "sidecar", "survivors": len(rows),
                "kept": [r.get("id") for r in rows],
                "verdict": "needs-source" if rows else "cited-empty",
                "advisory": True, "auto_credit": False}
        print(json.dumps(summ, indent=2))
        return 1 if (strict and rows) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    has_go = any(root.rglob("*.go")) if root.exists() else False
    substrate = "substrate_present" if has_go else "substrate_vacuous"
    res = analyze(root)
    # EMIT BY DEFAULT (2026-07-14): the step-2d-goroutine-race verifier checks
    # file_exists on the sidecar as proof-of-run ("empty = ran, 0 survivors"), and
    # the runbook documents the plain command with no --emit - so a genuine run
    # (0 survivors included) must write the cited-empty ledger. --no-emit opts out.
    if not args.no_emit:
        _emit_sidecar(ws, res["survivors"])
    summ = _summary(res, substrate)
    out = {"summary": summ}
    if not args.json:
        out["survivors"] = res["survivors"]
    print(json.dumps(out, indent=2))
    return 1 if (strict and res["survivors"]) else 0


if __name__ == "__main__":
    sys.exit(main())
