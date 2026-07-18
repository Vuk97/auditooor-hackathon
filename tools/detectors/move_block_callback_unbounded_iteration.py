#!/usr/bin/env python3
"""move_block_callback_unbounded_iteration - CHAIN-HALT detector (Move / Aptos-Sui).

The Move analog of the Go/Cosmos consensus-hook-unbounded-iteration miss. A function
reachable from a BLOCK / EPOCH callback (block_prologue, on_new_epoch, reconfiguration,
new_epoch, reconfigure, ...) - or a `public entry fun` that runs on the hot path -
loops (while / for / vector::for_each*) over a vector<T> or Table WHOSE LENGTH is
ATTACKER-GROWABLE via a PERMISSIONLESS `public entry fun` that pushes into that same
collection (vector::push_back / table::add / smart_vector::push_back / add) WITH NO CAP.

Unbounded per-block work -> block prologue exceeds the gas/time budget -> validators
cannot produce/execute the block -> CHAIN HALT.

MECHANISM=consensus-hook-unbounded-iteration  IMPACT=chain-halt  severity_hint=high.

Refute-first: a finding fires only when ALL of
  (1) the loop is reachable from a block/epoch callback OR a public entry fun, AND
  (2) the loop has NO in-scope cap (len compare -> break/return, or a Max*/limit const), AND
  (3) some collection it iterates is grown by a PERMISSIONLESS public entry fun with an
      uncapped push/add.
The negative fixture (a bounded loop / an admin-gated grow / a capped grow) stays clean.

Language-agnostic sibling detectors (Go/Cosmos BeginBlock, Substrate on_initialize) live
alongside; this is the Move arm.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

SCHEMA = "auditooor.mechanism_scan.consensus_hook_unbounded_iteration.move.v1"
MECHANISM = "consensus-hook-unbounded-iteration"
IMPACT = "chain-halt"
SOURCE_RECORD_ID = "aptos_block_prologue_unbounded_epoch_iteration + move_public_entry_growable_vector"

# ---- block / epoch callbacks (gas-unmetered or hot-path system callbacks) ----------
BLOCK_CALLBACK_NAMES = {
    "block_prologue", "block_prologue_ext", "on_new_epoch", "reconfiguration",
    "reconfigure", "new_epoch", "epilogue", "block_epilogue", "advance_epoch",
    "on_new_block", "prologue", "distribute", "process_collected_fees",
}
BLOCK_CALLBACK_HINT_RE = re.compile(
    r"(?i)\b(block_prologue|on_new_epoch|reconfigurat|new_epoch|advance_epoch|"
    r"block_epilogue|on_new_block)\b")

# ---- a Move function declaration --------------------------------------------------
# capture visibility+entry modifiers and the name.
FUNC_DECL_RE = re.compile(
    r"^\s*(?P<mods>(?:public(?:\s*\([^)]*\))?\s+|entry\s+|native\s+|inline\s+|friend\s+)*)"
    r"fun\s+(?P<name>[A-Za-z_]\w*)\s*(?:<[^>()]*>)?\s*\(")

# ---- a loop over a collection -----------------------------------------------------
FOR_EACH_RE = re.compile(
    r"\b(?:vector|smart_vector|big_vector|simple_map|smart_table)?::?"
    r"(?P<iter>for_each|for_each_ref|for_each_mut|for_each_reverse|enumerate_ref|any|all)\s*(?:<[^>()]*>)?\s*\(")
WHILE_RE = re.compile(r"\bwhile\s*\(")
FOR_RE = re.compile(r"\bfor\s*\(")

# receiver / collection expression that is being iterated. Matches the argument to a
# for_each (`vector::for_each(&self.queue, ...)`) or the len(...) used to drive a while.
LEN_RE = re.compile(
    r"\b(?:vector|smart_vector|big_vector|smart_table|table|simple_map)::length\s*\(\s*&?\s*"
    r"(?P<coll>[A-Za-z_][\w.]*)")
FOR_EACH_ARG_RE = re.compile(
    r"::for_each(?:_ref|_mut|_reverse)?\s*(?:<[^>()]*>)?\s*\(\s*&?\s*(?P<coll>[A-Za-z_][\w.]*)")

# ---- an in-scope cap on the loop (=> bounded, suppress) ---------------------------
CAP_IN_SCOPE_RE = re.compile(
    r"(?i)("
    r"MAX_\w*(?:BATCH|LIMIT|ITER|COUNT|SIZE|ENTRIES|ELEMENTS)"      # a named cap const
    r"|\bbatch_size\b|\bmax_batch\b|\bmax_iterations?\b"
    r"|if\s*\(\s*\w+\s*(?:>=|>)\s*\w+[\s\S]{0,80}?(?:break|return)"  # counter>=bound -> stop
    r"|\blimit\b\s*(?:-\s*=\s*1|<=|<)"                              # countdown limit
    r"|\bmath::min\b"                                              # min(len, cap) truncation
    r")")

# ---- a grow op (push/add) ---------------------------------------------------------
GROW_OP_RE = re.compile(
    r"\b(?:vector|smart_vector|big_vector|smart_table|table|simple_map)::"
    r"(?P<op>push_back|add|upsert|insert|append)\s*(?:<[^>()]*>)?\s*\(\s*&?\s*mut\s*"
    r"(?P<coll>[A-Za-z_][\w.]*)")
# fallback: `coll.push_back(` receiver-style
GROW_RECV_RE = re.compile(
    r"\b(?P<coll>[A-Za-z_][\w.]*)\.(?:push_back|add|upsert|insert|append)\s*\(")

# ---- an authority / admin gate inside a grow fn (=> not permissionless) -----------
AUTH_GATE_RE = re.compile(
    r"(?i)("
    r"assert!\s*\([^;]*(?:signer::address_of|is_owner|is_admin|only_owner|only_admin"
    r"|system_addresses|assert_aptos_framework|assert_governance|has_role|@aptos_framework"
    r"|account_addr\s*==|caller\s*==|==\s*@)[^;]*\)"
    r"|only_owner\s*\(|only_admin\s*\(|assert_owner\s*\(|assert_admin\s*\("
    r"|require_\w*(?:owner|admin|governance)"
    r")")
# a cap check inside a grow fn (=> the collection cannot grow unbounded)
GROW_CAP_RE = re.compile(
    r"(?i)(assert!\s*\([^;]*(?:length|len|size)\s*\([^;]*(?:<|<=)[\s\S]{0,40}?(?:MAX_|_MAX|limit|cap)"
    r"|assert!\s*\([^;]*(?:<|<=)\s*MAX_\w+)")


def _strip(line: str) -> str:
    """Drop Move // and quoted-string content (line-level; block /* */ handled in file pass)."""
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
        if c == '"':
            in_str = c
            i += 1
            continue
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _strip_block_comments(text: str) -> str:
    """Remove /* ... */ block comments (Move) preserving line count."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text[i] == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            if j == -1:
                # unterminated; keep newlines only
                out.append("\n" * text.count("\n", i))
                break
            out.append("\n" * text.count("\n", i, j + 2))
            i = j + 2
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _iter_funcs(lines: list[str]):
    """Yield (name, mods, decl_line, body_start, body_end) for every fun (brace-matched)."""
    i, n = 0, len(lines)
    while i < n:
        m = FUNC_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name, mods = m.group("name"), m.group("mods") or ""
        # native fun has no body
        if "native" in mods and "{" not in "".join(lines[i:i + 3]):
            i += 1
            continue
        depth, opened, body_start, j = 0, False, -1, i
        advanced = False
        while j < n:
            for ch in _strip(lines[j]):
                if ch == "{":
                    if not opened:
                        opened, body_start = True, j
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if opened and depth == 0:
                        yield name, mods, i, body_start, j
                        i = j + 1
                        advanced = True
                        break
            else:
                j += 1
                continue
            break
        if not advanced:
            return


def _move_files(root: str):
    if os.path.isfile(root):
        if root.endswith(".move"):
            yield root
        return
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if not d.startswith(".") and d not in (
            "build", "node_modules", "tests")]
        for fn in fns:
            if fn.endswith(".move"):
                yield os.path.join(dp, fn)


def _callees(body: list[str]) -> set[str]:
    """Bare function names invoked in a body (1-hop call targets), module-qualified stripped."""
    out: set[str] = set()
    for ln in body:
        s = _strip(ln)
        for m in re.finditer(r"(?:\b\w+::)?(?P<fn>[A-Za-z_]\w*)\s*(?:<[^>()]*>)?\s*\(", s):
            out.add(m.group("fn"))
    return out


def _norm_coll(expr: str) -> str:
    """Normalize a collection expr (self.queue / borrow_global<T>().q / q) to a comparable key."""
    e = expr.strip()
    # take the last path segment (self.pending_queue -> pending_queue)
    if "." in e:
        e = e.split(".")[-1]
    return e.lower()


def scan_root(root: str) -> dict:
    funcs: dict[str, list[dict]] = {}
    # permissionless grow: collection-name -> True if a public entry fun grows it uncapped/ungated
    grown_permissionless: dict[str, dict] = {}

    for path in _move_files(root):
        try:
            raw = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        raw = _strip_block_comments(raw)
        lines = raw.splitlines()
        for name, mods, decl, bs, be in _iter_funcs(lines):
            body = lines[bs:be + 1]
            body_txt = "\n".join(_strip(l) for l in body)
            is_public = "public" in mods
            is_entry = "entry" in mods
            funcs.setdefault(name, []).append({
                "path": path, "decl_line": decl + 1, "mods": mods,
                "is_public": is_public, "is_entry": is_entry,
                "body": body, "body_txt": body_txt,
            })
            # permissionless-grow detection: a public entry (or public) fun that grows a
            # collection with NO auth gate AND NO grow cap.
            if is_public or is_entry:
                gated = bool(AUTH_GATE_RE.search(body_txt))
                capped = bool(GROW_CAP_RE.search(body_txt))
                if not gated and not capped:
                    for gm in GROW_OP_RE.finditer(body_txt):
                        key = _norm_coll(gm.group("coll"))
                        grown_permissionless.setdefault(key, {
                            "grow_fn": name, "grow_file": path, "op": gm.group("op")})
                    for gm in GROW_RECV_RE.finditer(body_txt):
                        key = _norm_coll(gm.group("coll"))
                        grown_permissionless.setdefault(key, {
                            "grow_fn": name, "grow_file": path, "op": "push_back"})

    # block-callback-reachable set: callbacks + their 1-hop callees.
    callback_names = {n for n in funcs
                      if n in BLOCK_CALLBACK_NAMES or BLOCK_CALLBACK_HINT_RE.search(n)}
    reachable: dict[str, str] = {}  # fn -> the callback (or "entry") that reaches it
    for cn in callback_names:
        for occ in funcs.get(cn, []):
            reachable.setdefault(cn, cn)
            for callee in _callees(occ["body"]):
                if callee in funcs and callee not in callback_names:
                    reachable.setdefault(callee, cn)
    # public entry funs are directly hot-path reachable (anyone can call every block).
    for n, occs in funcs.items():
        if any(o["is_entry"] and o["is_public"] for o in occs):
            reachable.setdefault(n, "public_entry")

    findings: list[dict] = []
    for fn, via in reachable.items():
        for occ in funcs.get(fn, []):
            body = occ["body"]
            body_txt = occ["body_txt"]
            has_cap = bool(CAP_IN_SCOPE_RE.search(body_txt))
            for idx, ln in enumerate(body):
                s = _strip(ln)
                loop_kind = None
                if FOR_EACH_RE.search(s):
                    loop_kind = "for_each"
                elif WHILE_RE.search(s):
                    loop_kind = "while"
                elif FOR_RE.search(s):
                    loop_kind = "for"
                if not loop_kind:
                    continue
                if has_cap:
                    continue  # loop is bounded in this function scope
                # which collection does this loop iterate?
                coll = ""
                fam = FOR_EACH_ARG_RE.search(s)
                if fam:
                    coll = fam.group("coll")
                else:
                    lm = LEN_RE.search(s)
                    if lm:
                        coll = lm.group("coll")
                # while-loops may drive off a length computed on a nearby line: look at the
                # whole function for a length(coll) that has no cap.
                if not coll and loop_kind in ("while", "for"):
                    lm = LEN_RE.search(body_txt)
                    if lm:
                        coll = lm.group("coll")
                coll_key = _norm_coll(coll) if coll else ""
                grow = grown_permissionless.get(coll_key)
                # Refute-first: require a matching PERMISSIONLESS growable collection.
                if not grow:
                    continue
                findings.append({
                    "schema": SCHEMA,
                    "mechanism": MECHANISM,
                    "impact": IMPACT,
                    "severity_hint": "high",
                    "file": os.path.relpath(occ["path"], root) if os.path.isdir(root)
                            else os.path.basename(occ["path"]),
                    "line": occ["decl_line"] + idx,
                    "function": fn,
                    "reached_from_hook": via,
                    "loop_kind": loop_kind,
                    "collection": coll or "?",
                    "grow_fn": grow["grow_fn"],
                    "grow_op": grow["op"],
                    "reason": (
                        f"{loop_kind} loop over '{coll or '?'}' reachable from "
                        f"'{via}' has NO in-scope cap, while the permissionless "
                        f"'{grow['grow_fn']}' grows it via {grow['op']} with no auth "
                        f"gate or size cap -> unbounded per-block work halts the chain"),
                    "source_record_id": SOURCE_RECORD_ID,
                })
    findings.sort(key=lambda f: (f["file"], f["line"]))
    return {"schema": SCHEMA, "mechanism": MECHANISM, "impact": IMPACT,
            "root": root, "block_callbacks_found": sorted(callback_names),
            "permissionless_grown": sorted(grown_permissionless.keys()),
            "findings": findings, "finding_count": len(findings)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root", help="Move source tree (or single .move file) to scan")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    rep = scan_root(args.root)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"[move-block-callback-unbounded-iteration] "
              f"callbacks={rep['block_callbacks_found']} findings={rep['finding_count']}")
        for f in rep["findings"]:
            print(f"  [{f['severity_hint'].upper()}] {f['file']}:{f['line']} "
                  f"{f['function']} <- {f['reached_from_hook']} :: "
                  f"{f['loop_kind']}({f['collection']}) - {f['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
