#!/usr/bin/env python3
"""sol_ast_unbounded_attacker_growable_iteration - PERMANENT-FREEZE / loop-DoS detector.

The EVM analog of go_ast_consensus_hook_unbounded_iteration (the consensus-hook
class). Impact-first (primacy-of-impact) detector for the highest-value liveness
miss on Solidity: an external/public STATE-MUTATING function loops over a storage
array (via `<arr>.length`) or an OpenZeppelin EnumerableSet (via `.length()` /
`.at(i)`) with NO per-call cap on the iteration count, WHILE the SAME collection
is GROWN (`.push` / `.add` / `EnumerableSet.add`) by ANOTHER external/public
function that an UNPRIVILEGED caller can reach (no onlyOwner / onlyRole /
require(msg.sender == ...) guard on the grow path).

Join is by the COLLECTION IDENTIFIER (the storage variable name): the read-side
uncapped loop and the write-side unprivileged grow must touch the same storage
collection. When both hold, an attacker inflates the collection cheaply and the
loop later reverts on out-of-gas -> if the loop sits on the exit/withdraw/claim
path the funds are PERMANENTLY FROZEN (griefing loop-DoS).

Grounded in the SSV-style operator/validator/cluster registration surface: an
`registerOperator` / `bulkRegisterValidator` style function pushes into a shared
array/set that a fee-claim or withdraw loop later walks unbounded.

MECHANISM=unbounded-attacker-growable-iteration  IMPACT=permanent-freeze / DoS
severity_hint=high  (permanent-freeze when the loop is on the exit/withdraw path).

Refute-first / never-false-pass: a loop with an in-scope cap (compare-then-break,
a `< CAP` bound, a countdown limit) is NOT flagged, and a grow path guarded by
onlyOwner / onlyRole / require(msg.sender == ...) is NOT an attacker-growable
witness. Both sides must be genuinely unprivileged-reachable.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

SCHEMA = "auditooor.mechanism_scan.unbounded_attacker_growable_iteration.v1"
MECHANISM = "unbounded-attacker-growable-iteration"
IMPACT = "permanent-freeze / DoS"
SOURCE_RECORD_ID = (
    "ssv_operator_registration_unbounded_loop_class + "
    "evm_analog:go_ast_consensus_hook_unbounded_iteration")

# --- function declarations -------------------------------------------------
# Solidity function header; capture name + the modifier/visibility clause up to
# the opening brace (or ; for an abstract decl, which we skip - no body).
FUNC_DECL_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^;{]*?)\)"
    r"(?P<attrs>[^;{]*?)\{")
VISIBILITY_EXTERNAL_RE = re.compile(r"\b(external|public)\b")
STATE_MUTATING_RE = re.compile(r"\b(view|pure)\b")  # presence => NOT state-mutating

# --- privilege guards (presence on the grow path => NOT unprivileged) -------
PRIV_MODIFIER_RE = re.compile(
    r"\b(onlyOwner|onlyRole|onlyAdmin|onlyGovernance|onlyManager|onlyOperator"
    r"|onlyController|onlyGuardian|onlyKeeper|onlyAuthorized|restricted"
    r"|requiresAuth|auth)\b")
PRIV_REQUIRE_RE = re.compile(
    r"(?:require|_checkRole|_checkOwner|hasRole)\s*\([^;]*?"
    r"(?:msg\.sender\s*==|==\s*msg\.sender|msg\.sender\s*,\s*|owner\(\)"
    r"|_msgSender\(\)\s*==|==\s*_msgSender\(\))")
PRIV_REVERT_RE = re.compile(
    r"if\s*\(\s*(?:msg\.sender|_msgSender\(\))\s*!=[^)]*\)\s*(?:revert|_revert)")

# --- iteration read-side ---------------------------------------------------
# for/while whose condition references <collection>.length or <set>.length()
LOOP_HEAD_RE = re.compile(r"\b(for|while)\s*\(")
# .length (array) or .length() (EnumerableSet) usage of an identifier
LENGTH_USE_RE = re.compile(r"\b(?P<coll>[A-Za-z_]\w*)\s*\.\s*length\s*(?P<call>\(\s*\))?")
# EnumerableSet .at(i) read (strong signal of set iteration)
SET_AT_RE = re.compile(r"\b(?P<coll>[A-Za-z_]\w*)\s*\.\s*at\s*\(")

# --- in-scope cap signals (presence => the loop IS bounded) ----------------
# A named cap constant compared, a `< CAP` where CAP is not the .length, a
# counter-compare-then-break, or a bounded countdown.
CAP_CONST_RE = re.compile(
    r"(?i)\b(MAX\w*(?:LEN(?:GTH)?|BATCH|LIMIT|COUNT|SIZE|ITER\w*)|BATCH_?SIZE"
    r"|_?MAX_?\w*|maxLen\w*|maxBatch\w*|maxIter\w*|batchSize|_limit|pageSize)\b")
BREAK_STOP_RE = re.compile(r"\b(break|return)\b")

# --- grow-side -------------------------------------------------------------
# arr.push(...) or set.add(...) / EnumerableSet.add(set, ...)
PUSH_RE = re.compile(r"\b(?P<coll>[A-Za-z_]\w*)\s*\.\s*push\s*\(")
ADD_RE = re.compile(r"\b(?P<coll>[A-Za-z_]\w*)\s*\.\s*add\s*\(")
# EnumerableSet library-call form: EnumerableSet.add(myset, value) / .add(_set,
# value) where the SET is the FIRST argument.
LIB_ADD_RE = re.compile(
    r"\b(?:EnumerableSet\.)?(?:add|_add)\s*\(\s*(?P<coll>[A-Za-z_]\w*)\b")

# collection names that iterate/grow on the EXIT/withdraw/claim path -> freeze.
EXIT_PATH_RE = re.compile(
    r"(?i)(withdraw|redeem|exit|claim|unstake|payout|distribut\w*|settle"
    r"|liquidat\w*|remove|deregister|sweep)")


def _strip(text: str) -> str:
    """Remove // and /* */ comments and string/char literals (keep line count)."""
    out: list[str] = []
    i, n = 0, len(text)
    in_line, in_block, in_str = False, False, None
    while i < n:
        c = text[i]
        if in_line:
            if c == "\n":
                in_line = False
                out.append(c)
            i += 1
            continue
        if in_block:
            if c == "*" and i + 1 < n and text[i + 1] == "/":
                in_block = False
                i += 2
                continue
            out.append(c if c == "\n" else " ")
            i += 1
            continue
        if in_str:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            in_line = True
            i += 2
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            in_block = True
            i += 2
            continue
        if c in ('"', "'"):
            in_str = c
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _iter_funcs(src: str):
    """Yield (name, args, attrs, body, decl_line) for every solidity function
    with a body. `src` must already be comment/string-stripped. Brace-matched so
    nested blocks/modifiers stay inside the body."""
    for m in FUNC_DECL_RE.finditer(src):
        open_brace = src.index("{", m.start())
        depth, j, n = 0, open_brace, len(src)
        end = n
        while j < n:
            ch = src[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
            j += 1
        body = src[open_brace + 1:end]
        decl_line = src.count("\n", 0, m.start()) + 1
        yield (m.group("name"), m.group("args"), m.group("attrs"), body, decl_line)


def _sol_files(root: str):
    if os.path.isfile(root):
        if root.endswith(".sol"):
            yield root
        return
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if not d.startswith(".") and d.lower() not in (
            "node_modules", "lib", "test", "tests", "mocks", "mock", "script")]
        for fn in fns:
            if fn.endswith(".sol") and not fn.endswith(".t.sol"):
                yield os.path.join(dp, fn)


def _is_external_state_mutating(attrs: str) -> bool:
    return bool(VISIBILITY_EXTERNAL_RE.search(attrs)) and not STATE_MUTATING_RE.search(attrs)


def _is_unprivileged(attrs: str, body: str) -> bool:
    """True when NEITHER the modifier clause NOR the body enforces a caller check."""
    if PRIV_MODIFIER_RE.search(attrs):
        return False
    if PRIV_REQUIRE_RE.search(body):
        return False
    if PRIV_REVERT_RE.search(body):
        return False
    return True


def _loop_spans(body: str):
    """Yield (loop_header_str, body_offset_line, inner_body_str) for each loop."""
    for m in LOOP_HEAD_RE.finditer(body):
        # find the loop's paren-balanced header
        p = body.index("(", m.start())
        depth, j, n = 0, p, len(body)
        head_end = p
        while j < n:
            if body[j] == "(":
                depth += 1
            elif body[j] == ")":
                depth -= 1
                if depth == 0:
                    head_end = j
                    break
            j += 1
        header = body[p:head_end + 1]
        # inner block (up to a matching brace if a block, else the next stmt)
        k = head_end + 1
        while k < n and body[k] in " \t\r\n":
            k += 1
        inner = ""
        if k < n and body[k] == "{":
            depth, j = 0, k
            while j < n:
                if body[j] == "{":
                    depth += 1
                elif body[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            inner = body[k:j + 1]
        else:
            semi = body.find(";", k)
            inner = body[k:semi + 1] if semi != -1 else body[k:]
        line = body.count("\n", 0, m.start())
        yield header, line, inner


def _loop_has_cap(header: str, inner: str, collection: str) -> bool:
    """A loop is BOUNDED when it compares against a fixed cap rather than only the
    collection length, or breaks on a counter compare."""
    combined = header + "\n" + inner
    # A named cap constant that is NOT the collection's own .length.
    for cm in CAP_CONST_RE.finditer(combined):
        tok = cm.group(0)
        # ignore the collection itself masquerading as a cap
        if tok.lower() == collection.lower():
            continue
        return True
    # for (...; i < N; ...) where N is a plain numeric/const literal, not X.length
    cond = header
    # strip the collection-length term so a residual `< <cap>` counts
    cond_wo_len = re.sub(re.escape(collection) + r"\s*\.\s*length\s*(\(\s*\))?", "#LEN#", cond)
    if re.search(r"[<>]=?\s*(?:0x[0-9a-fA-F]+|\d+)\b", cond_wo_len):
        return True
    # counter-compare then break inside the body: if (x >= CAP) break;
    if re.search(r"if\s*\([^)]*[<>]=?[^)]*\)[\s\S]{0,60}?\b(break|return)\b", inner):
        # ensure the guard is not just `i < arr.length` (that's the loop bound)
        return True
    return False


def scan_root(root: str) -> dict:
    # 1. parse every function across the tree, keyed by name; also record which
    #    collections are GROWN by an unprivileged external/public function.
    funcs: list[dict] = []
    grown_unpriv: dict[str, list[dict]] = {}  # collection(lower) -> [grow occ]
    for path in _sol_files(root):
        try:
            raw = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        src = _strip(raw)
        for name, args, attrs, body, decl_line in _iter_funcs(src):
            rec = {"path": path, "name": name, "attrs": attrs, "body": body,
                   "decl_line": decl_line}
            funcs.append(rec)
            if not _is_external_state_mutating(attrs):
                continue
            if not _is_unprivileged(attrs, body):
                continue
            # record grows on this unprivileged path
            for gm in list(PUSH_RE.finditer(body)) + list(ADD_RE.finditer(body)):
                coll = gm.group("coll")
                if coll in ("memory",):
                    continue
                grown_unpriv.setdefault(coll.lower(), []).append(rec)
            for gm in LIB_ADD_RE.finditer(body):
                coll = gm.group("coll")
                grown_unpriv.setdefault(coll.lower(), []).append(rec)

    findings: list[dict] = []
    for rec in funcs:
        if not _is_external_state_mutating(rec["attrs"]):
            continue
        body = rec["body"]
        exit_path = bool(EXIT_PATH_RE.search(rec["name"]))
        for header, loop_line, inner in _loop_spans(body):
            scope = header + "\n" + inner
            # find the collection being iterated (array .length or set .length()/.at)
            colls: set[str] = set()
            for lm in LENGTH_USE_RE.finditer(scope):
                colls.add(lm.group("coll"))
            for am in SET_AT_RE.finditer(scope):
                colls.add(am.group("coll"))
            if not colls:
                continue
            for coll in sorted(colls):
                # is THIS collection grown by an unprivileged external fn elsewhere?
                grows = grown_unpriv.get(coll.lower())
                if not grows:
                    continue
                # refute: the loop is bounded in-scope -> not a freeze vector
                if _loop_has_cap(header, inner, coll):
                    continue
                grow_fns = sorted({g["name"] for g in grows})
                # exit-path OR grow-fn-on-exit => permanent-freeze; else DoS-high
                on_exit = exit_path or any(EXIT_PATH_RE.search(g["name"]) for g in grows)
                findings.append({
                    "schema": SCHEMA,
                    "mechanism": MECHANISM,
                    "impact": IMPACT,
                    "severity_hint": "high",
                    "file": os.path.relpath(rec["path"], root) if os.path.isdir(root)
                            else os.path.basename(rec["path"]),
                    "line": rec["decl_line"] + loop_line,
                    "function": rec["name"],
                    "collection": coll,
                    "grown_by": grow_fns,
                    "on_exit_path": on_exit,
                    "reason": (
                        f"external/public state-mutating '{rec['name']}' loops over "
                        f"'{coll}' via .length/.at with NO in-scope cap, while '{coll}' "
                        f"is grown by unprivileged fn(s) {grow_fns} (.push/.add with no "
                        f"onlyOwner/onlyRole/msg.sender guard) -> an attacker inflates "
                        f"'{coll}' cheaply and the loop reverts out-of-gas"
                        + (" on the exit/withdraw path -> PERMANENT FREEZE of funds"
                           if on_exit else " -> griefing loop-DoS")),
                    "source_record_id": SOURCE_RECORD_ID,
                })

    findings.sort(key=lambda f: (0 if f["on_exit_path"] else 1, f["file"], f["line"]))
    return {"schema": SCHEMA, "mechanism": MECHANISM, "impact": IMPACT,
            "root": root, "findings": findings, "finding_count": len(findings)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root", help="Solidity source tree or file to scan")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    rep = scan_root(args.root)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"[unbounded-attacker-growable-iteration] findings={rep['finding_count']}")
        for f in rep["findings"]:
            print(f"  [{f['severity_hint'].upper()}] {f['file']}:{f['line']} "
                  f"{f['function']} :: loop over {f['collection']} grown by "
                  f"{f['grown_by']} - {f['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
