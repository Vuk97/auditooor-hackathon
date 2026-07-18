#!/usr/bin/env python3
"""go_ast_consensus_hook_unbounded_iteration - CHAIN-HALT detector.

Impact-first (primacy-of-impact) detector for the highest-value liveness miss:
a GAS-UNMETERED consensus hook (Cosmos BeginBlock/EndBlock/PreBlock, or an ABCI
reconcile called from one) iterates a store/queue/collection with NO per-block
batch cap, while the collection is grown by a message an unprivileged caller can
send -> block time explodes -> validators time out -> CHAIN HALT.

Grounded in the NUVA/Provenance miss (nuva_chain_halt_lead_LIVE): BeginBlocker ->
handleVaultInterestTimeouts / handleVaultFeeTimeouts do PayoutTimeoutQueue.WalkDue
with no cap, WHILE the sibling EndBlocker path processPendingSwapOuts IS capped at
MaxSwapOutBatchSize=100. That SIBLING-CAP ASYMMETRY is the strongest smell: the
authors knew to bound one hook and left the others unbounded.

Scope: scans a Go package tree (hooks + their 1-hop callees may live in different
files, so this is a package-level scan, not per-file). Emits a common
mechanism-scan schema consumed by the completeness-matrix mechanism axis.

MECHANISM=consensus-hook-unbounded-iteration  IMPACT=chain-halt  severity>=high.
Language-agnostic sibling detectors (Substrate on_initialize/on_finalize, Move
block-callbacks) live alongside; this is the Go/Cosmos arm.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

SCHEMA = "auditooor.mechanism_scan.consensus_hook_unbounded_iteration.v1"
MECHANISM = "consensus-hook-unbounded-iteration"
IMPACT = "chain-halt"
SOURCE_RECORD_ID = "nuva_chain_halt_lead_LIVE + cosmos_sdk_ibc:endblocker-unbounded-queue"

# A consensus hook (gas-unmetered per-block callback).
HOOK_DECL_RE = re.compile(
    r"func\s*(?:\([^)]*\)\s*)?(?P<name>BeginBlock(?:er)?|EndBlock(?:er)?|PreBlock(?:er)?)\s*\(")
FUNC_DECL_RE = re.compile(r"^\s*func\s*(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\(")
# An unbounded store/collection walk.
WALK_RE = re.compile(
    r"\.(?P<walk>Walk|WalkDue|WalkByPrefix|Iterate|IterateAll|IterateRaw|Range|ReverseIterate)\s*\(")
# In-scope batch cap / bound signals (presence => the loop IS bounded). Covers:
# a named cap constant, and the counter-compare-then-STOP idiom where "stop" is
# either a Go `break` OR a `collections.Walk` callback `return true` (stop=true).
CAP_IN_SCOPE_RE = re.compile(
    r"(?i)("
    r"Max\w*(?:BatchSize|Batch|Limit|Count|Iterations?)|BatchSize|batchLimit"
    r"|if\s+\w+\s*(?:>=|>)\s*\w+[\s\S]{0,80}?(?:break|return\s+true)"   # counter>=bound -> stop
    r"|\blimit\b\s*(?:--|<=|<)"                                        # countdown limit
    r")")
# A call argument that looks like a batch cap (evidence a SIBLING call is capped).
CAP_ARG_RE = re.compile(r"(?i)\b(Max\w*(?:BatchSize|Batch|Limit|Count)|BatchSize|batchLimit|batchSize)\b")
# Names that indicate the collection is a growable queue/set/map.
GROWABLE_RECV_RE = re.compile(
    r"(?i)\b\w*(Queue|Set|Map|Pending|Timeout|Verification|Index|Store)\b")
# A grow op (enqueue/push/add/set) elsewhere -> the collection is attacker-growable-shaped.
GROW_OP_RE = re.compile(
    r"\.(Enqueue|Push|Append|Insert|Add|Set|Create|Register)\s*\(")

# ---------------------------------------------------------------------------
# hook-panic-no-recover arm (advisory-first, OFF by default).
#
# Predicate: a panic-source op (nil-map write, unguarded slice/map index,
# type-assert WITHOUT comma-ok, unchecked / or %) inside a body reachable from a
# Begin/End/PreBlock hook, with NO recover() on the path. A Cosmos consensus hook
# has NO gas meter and its panic is NOT recovered by the SDK for Begin/End/PreBlock
# -> an unprivileged input that reaches the op halts the chain. mechanism=
# hook-panic-no-recover impact=chain-halt. Emitted verdict is ALWAYS 'needs-fuzz'
# (NO-AUTO-CREDIT): reachability of the tainted operand is a fuzz obligation, never
# a self-credited finding.
PANIC_SCHEMA = "auditooor.hypothesis.hook_panic_no_recover.v1"
PANIC_MECHANISM = "hook-panic-no-recover"
# Advisory env: emission is OFF unless this is truthy (advisory-first: a NEW,
# high-FP mechanism must not retroactively re-open a parked audit).
PANIC_ENV = "AUDITOOOR_HOOK_PANIC_RECOVER"
# Reachability hop bound (hook -> callee -> callee ...). Default 3 so a hook's
# 2nd/3rd-hop worker (e.g. EndBlocker -> processPendingSwapOuts -> processSwapOutJobs)
# is covered. hops=1 reproduces the unbounded-iteration arm's 1-hop reach.
PANIC_HOPS_ENV = "AUDITOOOR_HOOK_PANIC_HOPS"
PANIC_SOURCE_RECORD_ID = "nuva_chain_halt_lead_LIVE + cosmos_sdk:beginblock-panic-halts-chain"

# A type assertion x.(T) (single-return form panics on mismatch). '.(type)' is a
# type switch, not an assertion - excluded below.
TYPE_ASSERT_RE = re.compile(r"\.\(\s*(?:\*\s*)?(?:\[\]\s*)?(?P<t>[A-Za-z_][\w.]*)\s*\)")
# comma-ok guard on the SAME line: `v, ok := x.(T)` / `v, ok = x.(T)` -> safe.
COMMA_OK_RE = re.compile(r",\s*\w+\s*:?=\s*[^,]*\.\(")
# An index-assignment `x[k] = ...` (nil-map write or slice OOB write). Not '=='.
IDX_WRITE_RE = re.compile(r"(?<![=!<>+\-*/%|&^:])\b(?P<recv>\w+)\s*\[[^\]]+\]\s*=(?!=)")
# Division / modulo by a NON-literal operand (a numeric literal does not start
# with a letter/underscore, so only variable divisors match => are suspect).
DIV_RE = re.compile(r"[)\w\].]\s*(?P<op>[/%])\s*(?P<div>[A-Za-z_]\w*)")
RECOVER_RE = re.compile(r"\brecover\s*\(")
# Safe arithmetic helpers / error-returning math => the op is guarded upstream.
SAFE_HELPER_RE = re.compile(r"\b(?:Safe(?:Sub|Add|Mul|Div|Quo|Rem)\w*|QuoRem|checked\w*)\s*\(")


def _strip(line: str) -> str:
    out: list[str] = []
    i, in_str = 0, None
    while i < len(line):
        c = line[i]
        if in_str:
            if c == "\\" and i + 1 < len(line):
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'", "`"):
            in_str = c
            i += 1
            continue
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _iter_funcs(lines: list[str]):
    """Yield (name, decl_line, body_start, body_end) for every top-level func."""
    i, n = 0, len(lines)
    while i < n:
        if not FUNC_DECL_RE.match(lines[i]):
            i += 1
            continue
        name = FUNC_DECL_RE.match(lines[i]).group("name")
        depth, opened, body_start, j = 0, False, -1, i
        while j < n:
            for ch in _strip(lines[j]):
                if ch == "{":
                    if not opened:
                        opened, body_start = True, j
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if opened and depth == 0:
                        yield name, i, body_start, j
                        i = j + 1
                        break
            else:
                j += 1
                continue
            break
        else:
            return


def _go_files(root: str):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if not d.startswith(".") and d not in (
            "vendor", "node_modules", "testdata")]
        for fn in fns:
            if fn.endswith(".go") and not fn.endswith("_test.go"):
                yield os.path.join(dp, fn)


def _callees(body: list[str]) -> set[str]:
    """Bare function/method names invoked in a body (1-hop call targets)."""
    out: set[str] = set()
    for ln in body:
        s = _strip(ln)
        for m in re.finditer(r"(?:\b\w+\.)?(?P<fn>[A-Za-z_]\w*)\s*\(", s):
            out.add(m.group("fn"))
    return out


def _build_funcs(root: str):
    """Collect every func body across the package tree (name may collide across
    files/methods; keep a list per name). Also flags dirs where some call passes a
    batch-cap arg. Shared by both the unbounded-iteration and panic-no-recover arms."""
    funcs: dict[str, list[dict]] = {}
    module_has_cap_arg: dict[str, bool] = {}
    for path in _go_files(root):
        try:
            lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            continue
        d = os.path.dirname(path)
        for name, decl, bs, be in _iter_funcs(lines):
            body = lines[bs:be + 1]
            funcs.setdefault(name, []).append({
                "path": path, "dir": d, "decl_line": decl + 1,
                "body": body, "raw": lines,
            })
            for ln in body:
                if CAP_ARG_RE.search(_strip(ln)):
                    module_has_cap_arg[d] = True
    return funcs, module_has_cap_arg


def _hook_names(funcs: dict) -> set:
    """Names in `funcs` that are (or shadow) a Begin/End/PreBlock consensus hook."""
    return {n for n in funcs if HOOK_DECL_RE.search("func " + n + "(") or n in (
        "BeginBlock", "BeginBlocker", "EndBlock", "EndBlocker", "PreBlock", "PreBlocker")}


def _reachable_set(funcs: dict, hook_names: set, hops: int = 1) -> dict:
    """BFS from the hooks over resolved-in-pkg callees up to `hops` levels.
    Returns {fn name -> the hook that reaches it}. hops=1 == the 1-hop-callee
    walker the unbounded-iteration arm uses; the panic arm extends it to hops=3."""
    reachable: dict[str, str] = {n: n for n in hook_names if n in funcs}
    frontier = dict(reachable)
    for _ in range(max(1, hops)):
        nxt: dict[str, str] = {}
        for fn, via in frontier.items():
            for occ in funcs.get(fn, []):
                for callee in _callees(occ["body"]):
                    if callee in funcs and callee not in hook_names and callee not in reachable:
                        reachable[callee] = via
                        nxt[callee] = via
        frontier = nxt
        if not frontier:
            break
    return reachable


def scan_root(root: str) -> dict:
    # 1. collect every func body across the package tree.
    funcs, module_has_cap_arg = _build_funcs(root)
    # 2. hook-reachable set: hooks + their 1-hop callees (resolved within pkg).
    hook_names = _hook_names(funcs)
    reachable = _reachable_set(funcs, hook_names, hops=1)

    # a growable-collection name is one that appears in a GROW op somewhere.
    grown: set[str] = set()
    for occs in funcs.values():
        for occ in occs:
            for ln in occ["body"]:
                s = _strip(ln)
                if GROW_OP_RE.search(s):
                    for m in re.finditer(r"\b(\w*(?:Queue|Set|Map|Pending|Timeout|Verification|Index|Store))\b\.", s):
                        grown.add(m.group(1).lower())

    findings: list[dict] = []
    for fn, via_hook in reachable.items():
        for occ in funcs.get(fn, []):
            body = occ["body"]
            body_txt = "\n".join(_strip(l) for l in body)
            has_cap = bool(CAP_IN_SCOPE_RE.search(body_txt))
            for idx, ln in enumerate(body):
                s = _strip(ln)
                wm = WALK_RE.search(s)
                if not wm:
                    continue
                if has_cap:
                    continue  # the loop is bounded in this function scope
                # the receiver of the walk
                recv = ""
                rm = re.search(r"(\w+)\." + wm.group("walk"), s)
                if rm:
                    recv = rm.group(1)
                growable = bool(GROWABLE_RECV_RE.search(s)) or recv.lower() in grown
                sibling_cap = module_has_cap_arg.get(occ["dir"], False)
                # severity: CRITICAL when a sibling hook IS capped (asymmetry) AND
                # the walked collection is growable-shaped; else HIGH.
                sev = "critical" if (sibling_cap and growable) else "high"
                findings.append({
                    "schema": SCHEMA,
                    "mechanism": MECHANISM,
                    "impact": IMPACT,
                    "severity_hint": sev,
                    "file": os.path.relpath(occ["path"], root),
                    "line": occ["decl_line"] + idx,
                    "function": fn,
                    "reached_from_hook": via_hook,
                    "walk": wm.group("walk"),
                    "receiver": recv,
                    "collection_growable": growable,
                    "sibling_hook_capped": sibling_cap,
                    "reason": (
                        f"consensus-hook-reachable ({via_hook}) {wm.group('walk')} over "
                        f"'{recv or '?'}' has NO per-block batch cap"
                        + (" while a sibling call in this module passes a batch cap "
                           "(asymmetry) and the collection is growable -> unprivileged "
                           "queue growth halts the chain" if sev == "critical"
                           else "; verify the walked set is unprivileged-growable")),
                    "source_record_id": SOURCE_RECORD_ID,
                })
    findings.sort(key=lambda f: (0 if f["severity_hint"] == "critical" else 1, f["file"], f["line"]))
    return {"schema": SCHEMA, "mechanism": MECHANISM, "impact": IMPACT,
            "root": root, "hooks_found": sorted(hook_names),
            "findings": findings, "finding_count": len(findings)}


def _init_recvs(body_txt: str) -> set:
    """Receivers PROVABLY initialized in-body (make(...) / composite literal /
    :=map[..]{..}) -> writing them is NOT a nil-map write."""
    out: set = set()
    for m in re.finditer(r"\b(\w+)\s*(?::?=)\s*make\s*\(", body_txt):
        out.add(m.group(1))
    for m in re.finditer(r"\b(\w+)\s*(?::?=)\s*(?:map\[[^\]]+\][\w.\[\]*]+|\[\][\w.]+)\s*\{", body_txt):
        out.add(m.group(1))
    return out


def _panic_ops(body: list, body_txt: str) -> list:
    """Unguarded panic-source ops in a body whose path has NO recover().
    FP-guard: recover-absent (whole body), plus per-op local guards -
    comma-ok for type-asserts, divisor zero-check / Safe-helper for / and %,
    make()/len() init for index writes. Returns [(idx, kind, token, why)]."""
    if RECOVER_RE.search(body_txt):
        return []  # deferred recover on the path -> panic is caught, not a halt.
    inited = _init_recvs(body_txt)
    ops: list = []
    for idx, ln in enumerate(body):
        s = _strip(ln)
        if not s.strip():
            continue
        # 1. nil-map write / slice-index write: x[k] = ...  (not '==', not init'd).
        for m in IDX_WRITE_RE.finditer(s):
            recv = m.group("recv")
            if recv in inited:
                continue
            if re.search(r"\blen\s*\(\s*" + re.escape(recv) + r"\b", body_txt):
                continue  # a len() bound on the same receiver -> guarded index.
            ops.append((idx, "index-write", recv,
                        f"write '{recv}[..]=' on a receiver not make()-init'd on the path (nil-map/OOB panic)"))
        # 2. type assertion without comma-ok.
        if not COMMA_OK_RE.search(s):
            for m in TYPE_ASSERT_RE.finditer(s):
                t = m.group("t")
                if t == "type":
                    continue  # a type switch, not an assertion.
                ops.append((idx, "type-assert-no-comma-ok", t,
                            f"single-return type-assert '.({t})' panics on type mismatch (no comma-ok)"))
        # 3. unchecked division / modulo by a variable divisor.
        if not SAFE_HELPER_RE.search(s):
            for m in DIV_RE.finditer(s):
                div = m.group("div")
                zchk = re.search(r"\b" + re.escape(div) + r"\b\s*(?:==|!=)\s*0"
                                 r"|0\s*(?:==|!=)\s*\b" + re.escape(div) + r"\b", body_txt)
                if zchk:
                    continue  # divisor is zero-checked in-body -> guarded.
                ops.append((idx, "unchecked-div", div,
                            f"'{m.group('op')} {div}' with no in-body zero-check on '{div}' (div-by-zero panic)"))
    return ops


def scan_panic_no_recover(root: str, hops: int | None = None,
                          dedup_against=None) -> dict:
    """hook-panic-no-recover arm. Emits verdict='needs-fuzz' hypotheses (NO-AUTO-
    CREDIT). DEDUP boundary (A1): a hit whose (file, function) is ALREADY flagged by
    the unbounded-iteration arm is marked covered_by that detector - the covered_by
    signal is consumed from the sibling detector's own findings, never re-derived."""
    if hops is None:
        try:
            hops = int(os.environ.get(PANIC_HOPS_ENV, "") or 3)
        except ValueError:
            hops = 3
    funcs, _cap = _build_funcs(root)
    hook_names = _hook_names(funcs)
    reachable = _reachable_set(funcs, hook_names, hops=hops)

    # DEDUP: pull (file, function) already owned by the sibling unbounded arm.
    if dedup_against is None:
        try:
            dedup_against = scan_root(root).get("findings", [])
        except Exception:
            dedup_against = []
    covered = {(f.get("file"), f.get("function")) for f in dedup_against}

    hyps: list = []
    for fn, via_hook in reachable.items():
        for occ in funcs.get(fn, []):
            body = occ["body"]
            body_txt = "\n".join(_strip(l) for l in body)
            rel = os.path.relpath(occ["path"], root)
            for idx, kind, token, why in _panic_ops(body, body_txt):
                cov = (rel, fn) in covered
                hyps.append({
                    "schema": PANIC_SCHEMA,
                    "mechanism": PANIC_MECHANISM,
                    "impact": IMPACT,
                    "verdict": "needs-fuzz",           # NO-AUTO-CREDIT
                    "severity_hint": "high",
                    "file": rel,
                    "line": occ["decl_line"] + idx,
                    "function": fn,
                    "reached_from_hook": via_hook,
                    "hops": hops,
                    "panic_kind": kind,
                    "operand": token,
                    "recover_on_path": False,
                    "covered_by": "consensus-hook-unbounded-iteration" if cov else None,
                    "reason": (
                        f"hook-reachable ({via_hook}) {why}; no recover() on the path "
                        f"-> an unprivileged input reaching it panics a gas-unmetered "
                        f"consensus hook = CHAIN HALT. Fuzz the operand's reachability."),
                    "source_record_id": PANIC_SOURCE_RECORD_ID,
                })
    # Emitted set excludes dedup-covered hits (they belong to the sibling arm).
    emitted = [h for h in hyps if not h["covered_by"]]
    emitted.sort(key=lambda h: (h["file"], h["line"]))
    return {"schema": PANIC_SCHEMA, "mechanism": PANIC_MECHANISM, "impact": IMPACT,
            "root": root, "hops": hops, "hooks_found": sorted(hook_names),
            "hypotheses": emitted, "hypothesis_count": len(emitted),
            "covered_dedup_count": sum(1 for h in hyps if h["covered_by"])}


def _emit_panic_hypotheses(root: str, out_path: str) -> dict:
    """Advisory-first jsonl emit, GATED on PANIC_ENV (OFF by default)."""
    on = os.environ.get(PANIC_ENV, "").strip().lower() in ("1", "true", "yes", "on")
    if not on:
        return {"emitted": False, "reason": f"{PANIC_ENV} not set (advisory-first, OFF by default)"}
    rep = scan_panic_no_recover(root)
    with open(out_path, "w", encoding="utf-8") as fh:
        for h in rep["hypotheses"]:
            fh.write(json.dumps(h, sort_keys=True) + "\n")
    return {"emitted": True, "path": out_path, "count": rep["hypothesis_count"],
            "covered_dedup_count": rep["covered_dedup_count"]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root", help="Go source tree to scan (package/module root)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--panic-scan", action="store_true",
                    help="run the hook-panic-no-recover arm (advisory) instead")
    ap.add_argument("--panic-hypotheses", metavar="PATH",
                    help=f"emit needs-fuzz hypotheses jsonl (gated on ${PANIC_ENV})")
    args = ap.parse_args(argv)
    if args.panic_hypotheses:
        res = _emit_panic_hypotheses(args.root, args.panic_hypotheses)
        print(json.dumps(res, indent=2))
        return 0
    if args.panic_scan:
        rep = scan_panic_no_recover(args.root)
        if args.json:
            print(json.dumps(rep, indent=2))
        else:
            print(f"[hook-panic-no-recover] hooks={rep['hooks_found']} "
                  f"hyps={rep['hypothesis_count']} deduped={rep['covered_dedup_count']}")
            for h in rep["hypotheses"]:
                print(f"  [needs-fuzz] {h['file']}:{h['line']} {h['function']} "
                      f"<- {h['reached_from_hook']} :: {h['panic_kind']}({h['operand']})")
        return 0
    rep = scan_root(args.root)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"[consensus-hook-unbounded-iteration] hooks={rep['hooks_found']} "
              f"findings={rep['finding_count']}")
        for f in rep["findings"]:
            print(f"  [{f['severity_hint'].upper()}] {f['file']}:{f['line']} "
                  f"{f['function']} <- {f['reached_from_hook']} :: {f['walk']}({f['receiver']}) "
                  f"- {f['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
