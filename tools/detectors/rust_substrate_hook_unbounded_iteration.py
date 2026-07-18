#!/usr/bin/env python3
"""rust_substrate_hook_unbounded_iteration - CHAIN-HALT detector (Substrate/FRAME arm).

Impact-first (primacy-of-impact) detector for the highest-value liveness miss in
a Substrate/FRAME pallet: a block-import consensus hook - the `Hooks` impl fns
`on_initialize` / `on_finalize` / `on_idle` / `on_poll` - iterates a
`StorageMap` / `StorageDoubleMap` / `CountedStorageMap` via `.iter()` /
`.iter_keys()` / `.drain()` (or their prefix/from variants) with NO per-block
bound, WHILE the map is grown by a permissionless `#[pallet::call]` extrinsic
(an extrinsic whose body does NOT gate on `ensure_root` / a privileged
`T::Authority`-style origin - `ensure_signed` alone is NOT a bound, any funded
account passes it). Unbounded per-block work -> the block-import / on_initialize
weight explodes past the block weight limit -> no block can be produced ->
CHAIN HALT.

This is the Substrate analog of the Go/Cosmos BeginBlock/EndBlock unbounded-queue
miss (go_ast_consensus_hook_unbounded_iteration). FRAME hooks run every block
inside block execution; `on_initialize` and `on_finalize` in particular MUST
return a bounded weight or the runtime bricks. The strongest smell (borrowed
from the Cosmos sibling-cap asymmetry) is when ANOTHER hook in the same pallet
DOES bound its iteration (a `WeightMeter` budget early-return, a `.take(N)`, or a
counter-compare `break`) - the authors knew to bound one hook and left another
unbounded.

Mirrors the reference detector's structure: a brace-matched func-body walker
(`_iter_funcs`) over comment/string-stripped Rust source, a package-level scan
(the hook, the growing extrinsic, and the map declaration can live in different
files), and the common mechanism-scan finding schema.

MECHANISM=consensus-hook-unbounded-iteration  IMPACT=chain-halt  severity>=high.
Refute-first: only an unprivileged-reachable, unbounded, hook-iterated map is
flagged; a bounded hook (WeightMeter/take/BoundedVec) or a root-gated grower
stays clean.
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
SOURCE_RECORD_ID = (
    "substrate_frame_hook_unbounded_iteration:on_initialize-storagemap-iter"
    " + xref go_ast_consensus_hook_unbounded_iteration:endblocker-unbounded-queue")

# FRAME block-import consensus hooks (run every block inside block execution).
HOOK_FNS = ("on_initialize", "on_finalize", "on_idle", "on_poll", "on_runtime_upgrade")
HOOK_FN_RE = re.compile(
    r"^\s*fn\s+(?P<name>on_initialize|on_finalize|on_idle|on_poll|on_runtime_upgrade)\b")
# Any fn declaration (for the brace-matched body walker).
FN_DECL_RE = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z_]\w*)\b")

# An unbounded storage iteration: StorageMap::iter / iter_keys / iter_values /
# iter_from / drain / drain_prefix etc. Substrate storage items are iterated via
# the ASSOCIATED-fn form `Map::<T>::iter()` (a `::` call), not `.iter()`, so we
# accept a `::` or `.` connector before the verb.
ITER_RE = re.compile(
    r"(?:::|\.)\s*(?P<iter>iter_keys|iter_values|iter_from|iter_prefix_values"
    r"|iter_prefix|drain_prefix|drain|iter)\s*\(")

# In-scope per-block bound signals (presence => the hook loop IS bounded):
#   - a WeightMeter / weight-budget early-return
#   - a bounded .take(N) / .step_by-style cap on the iterator
#   - a BoundedVec typed collection
#   - a counter-compare-then-break idiom
BOUND_IN_SCOPE_RE = re.compile(
    r"(?i)("
    r"WeightMeter|weight_meter|remaining_weight|meter\.(?:try_consume|consume|check_accrue)"
    r"|\.take\s*\(\s*\w+\s*\)"                                  # bounded .take(N)
    r"|BoundedVec\b|BoundedBTreeMap\b"
    r"|Max\w*(?:Iterations?|BatchSize|Batch|Limit|Count|Entries|Items)"
    r"|if\s+\w+\s*(?:>=|>)\s*\w+[\s\S]{0,80}?break"            # counter>=bound -> break
    r"|\blimit\b\s*(?:-=|<=|<)"                                 # countdown limit
    r")")
# A cap/take/meter used somewhere in a hook body -> a SIBLING hook bounds (asymmetry).
SIBLING_BOUND_RE = BOUND_IN_SCOPE_RE

# StorageMap-family declarations (the type of an iterable pallet storage item).
STORAGE_DECL_RE = re.compile(
    r"type\s+(?P<name>[A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*=\s*"
    r"StorageMap\s*<|"
    r"type\s+(?P<name2>[A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*=\s*"
    r"(?:StorageDoubleMap|CountedStorageMap|StorageNMap)\s*<")
# `#[pallet::storage]` attribute (the alias that follows is a storage item).
STORAGE_ATTR_RE = re.compile(r"#\[\s*pallet::storage\s*[\]\(]")
STORAGE_ALIAS_RE = re.compile(r"type\s+(?P<name>[A-Za-z_]\w*)\b")

# A grow op on a map: insert / try_mutate / append / mutate that creates a key.
# Handles the turbofish form `Map::<T>::insert(...)` and the plain `Map::insert`.
GROW_OP_RE = re.compile(
    r"(?P<recv>[A-Za-z_]\w*)\s*::\s*(?:<[^;{}]*?>\s*::\s*)?"
    r"(?:insert|try_mutate|mutate|append|set)\s*\(")

# Extrinsic (permissionless-writable) markers.
CALL_ATTR_RE = re.compile(r"#\[\s*pallet::(?:call_index|weight)")
# A privileged-origin gate inside an extrinsic body (=> NOT permissionless).
PRIV_ORIGIN_RE = re.compile(
    r"(?i)(ensure_root\s*\(|EnsureRoot\b|ensure_root_or|"
    r"T::(?:Authority|AdminOrigin|GovernanceOrigin|ForceOrigin|ManagerOrigin|"
    r"ControlOrigin|UpdateOrigin)\b|"
    r"ensure_signed_or_root|ensure_none\s*\()")
# ensure_signed alone is NOT a bound (any funded account passes it).
ENSURE_SIGNED_RE = re.compile(r"ensure_signed\s*\(")


def _strip(text: str) -> str:
    """Remove // and /* */ comments and blank out string/char literal contents."""
    out: list[str] = []
    i, n = 0, len(text)
    in_line_c = False
    block_depth = 0
    in_str = None  # '"' or "'"
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line_c:
            if c == "\n":
                in_line_c = False
                out.append(c)
            i += 1
            continue
        if block_depth > 0:
            if c == "/" and nxt == "*":
                block_depth += 1
                i += 2
                continue
            if c == "*" and nxt == "/":
                block_depth -= 1
                i += 2
                continue
            if c == "\n":
                out.append(c)
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
        # not in comment/string
        if c == "/" and nxt == "/":
            in_line_c = True
            i += 2
            continue
        if c == "/" and nxt == "*":
            block_depth += 1
            i += 2
            continue
        if c in ('"', "'"):
            # crude: treat as string start (Rust lifetimes like 'a would be rare
            # inside bodies we care about; safe to blank).
            in_str = c
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _strip_lines(lines: list[str]) -> list[str]:
    """Strip comments/strings across the whole file, preserving line count."""
    stripped = _strip("\n".join(lines))
    return stripped.split("\n")


def _iter_funcs(slines: list[str]):
    """Yield (name, decl_idx, body_start, body_end) for every fn, brace-matched.

    Operates on already-comment/string-stripped lines.
    """
    i, n = 0, len(slines)
    while i < n:
        m = FN_DECL_RE.match(slines[i])
        if not m:
            i += 1
            continue
        name = m.group("name")
        depth, opened, body_start, j = 0, False, -1, i
        advanced = False
        while j < n:
            for ch in slines[j]:
                if ch == "{":
                    if not opened:
                        opened, body_start = True, j
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if opened and depth == 0:
                        yield name, i, body_start, j
                        i = j + 1
                        advanced = True
                        break
            else:
                j += 1
                continue
            break
        if not advanced:
            # unterminated (e.g. a trait fn signature `fn foo();` with no body)
            i += 1


def _rust_files(root: str):
    if os.path.isfile(root) and root.endswith(".rs"):
        yield root
        return
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if not d.startswith(".") and d not in (
            "target", "node_modules")]
        for fn in fns:
            if fn.endswith(".rs"):
                yield os.path.join(dp, fn)


def _storage_map_names(slines: list[str], raw: list[str]) -> set[str]:
    """StorageMap-family item names declared in this file (via type = StorageMap<..>
    or a `#[pallet::storage]` alias)."""
    names: set[str] = set()
    txt = "\n".join(slines)
    for m in STORAGE_DECL_RE.finditer(txt):
        nm = m.group("name") or m.group("name2")
        if nm:
            names.add(nm)
    # #[pallet::storage] alias form: attr on one line, `type Alias<...>` next.
    for idx, ln in enumerate(slines):
        if STORAGE_ATTR_RE.search(ln):
            for k in range(idx + 1, min(idx + 5, len(slines))):
                am = STORAGE_ALIAS_RE.search(slines[k])
                if am:
                    names.add(am.group("name"))
                    break
    return names


def scan_root(root: str) -> dict:
    # 1. gather every fn body across the tree; collect storage-map item names and
    #    which items are grown by a permissionless extrinsic.
    files: list[dict] = []
    storage_maps: set[str] = set()
    grown_permissionless: set[str] = set()  # map names grown by a non-root extrinsic
    grown_any: set[str] = set()

    parsed: list[tuple[str, list[str], list[str]]] = []  # (path, raw, stripped)
    for path in _rust_files(root):
        try:
            raw = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            continue
        slines = _strip_lines(raw)
        parsed.append((path, raw, slines))
        storage_maps |= _storage_map_names(slines, raw)

    for path, raw, slines in parsed:
        # find extrinsic call bodies: an extrinsic is a fn immediately preceded
        # (within a few lines) by a #[pallet::call_index]/#[pallet::weight] attr,
        # OR any pub fn that takes `origin` and is inside a `#[pallet::call]` impl.
        # We approximate: a fn whose signature mentions `origin` is an extrinsic.
        for name, decl, bs, be in _iter_funcs(slines):
            body = slines[bs:be + 1]
            sig = " ".join(slines[decl:bs + 1])
            is_extrinsic = ("origin" in sig) and bool(re.search(r"OriginFor|T::RuntimeOrigin|origin\s*:", sig))
            body_txt = "\n".join(body)
            privileged = bool(PRIV_ORIGIN_RE.search(body_txt)) or bool(PRIV_ORIGIN_RE.search(sig))
            grows_here: set[str] = set()
            for gm in GROW_OP_RE.finditer(body_txt):
                recv = gm.group("recv")
                if recv in storage_maps:
                    grows_here.add(recv)
            grown_any |= grows_here
            if is_extrinsic and not privileged and grows_here:
                grown_permissionless |= grows_here

    # 2. detect: hook fns iterating a storage map with no in-scope bound.
    #    sibling-cap asymmetry = another hook fn in the SAME file bounds.
    findings: list[dict] = []
    for path, raw, slines in parsed:
        hook_fns_here: list[tuple[str, int, int, int]] = []
        for name, decl, bs, be in _iter_funcs(slines):
            if HOOK_FN_RE.match(slines[decl]):
                hook_fns_here.append((name, decl, bs, be))
        if not hook_fns_here:
            continue
        # which hooks in this file are bounded?
        bounded_hook = {}
        for name, decl, bs, be in hook_fns_here:
            body_txt = "\n".join(slines[bs:be + 1])
            bounded_hook[(name, decl)] = bool(SIBLING_BOUND_RE.search(body_txt))
        any_sibling_bounds = any(bounded_hook.values())

        for name, decl, bs, be in hook_fns_here:
            body = slines[bs:be + 1]
            body_txt = "\n".join(body)
            if BOUND_IN_SCOPE_RE.search(body_txt):
                continue  # this hook is bounded
            for idx, ln in enumerate(body):
                im = ITER_RE.search(ln)
                if not im:
                    continue
                # receiver of the iteration; handle turbofish `Map::<T>::iter()`
                # and plain `Map::iter()` / `something.iter()`.
                recv = ""
                itn = im.group("iter")
                rm = re.search(
                    r"([A-Za-z_]\w*)\s*::\s*(?:<[^;{}]*?>\s*::\s*)?" + itn + r"\s*\(", ln)
                if not rm:
                    rm = re.search(r"([A-Za-z_]\w*)\s*\.\s*" + itn + r"\s*\(", ln)
                if rm:
                    recv = rm.group(1)
                iterates_storage_map = recv in storage_maps
                # if we can't resolve the receiver to a known storage map, still
                # flag when the iteration verb is a raw storage drain/iter and a
                # storage map exists in the tree (refute-first: prefer a resolved
                # map, but a bare `.iter()` inside a hook over a Self::-style item
                # is the classic shape). Require map-linkage to avoid FP on
                # Vec/BTreeMap locals.
                if not iterates_storage_map:
                    continue
                permissionless = recv in grown_permissionless
                # only flag a genuinely unprivileged-reachable instance
                if not permissionless:
                    continue
                # sibling asymmetry: another hook here bounds
                sib = any_sibling_bounds
                sev = "critical" if sib else "high"
                findings.append({
                    "schema": SCHEMA,
                    "mechanism": MECHANISM,
                    "impact": IMPACT,
                    "severity_hint": sev,
                    "file": os.path.relpath(path, root) if os.path.isdir(root) else os.path.basename(path),
                    "line": decl + 1 + idx,
                    "function": name,
                    "hook": name,
                    "iter": im.group("iter"),
                    "receiver": recv,
                    "storage_map": recv,
                    "permissionless_grower": True,
                    "sibling_hook_bounded": sib,
                    "reason": (
                        f"consensus hook '{name}' iterates StorageMap '{recv}' via "
                        f".{im.group('iter')}() with NO per-block bound "
                        f"(no WeightMeter/take(N)/BoundedVec), while '{recv}' is grown "
                        f"by a permissionless extrinsic -> unbounded block-import work "
                        f"-> CHAIN HALT"
                        + (" (a SIBLING hook in this pallet DOES bound its iteration - "
                           "author-known asymmetry)" if sib else "")),
                    "source_record_id": SOURCE_RECORD_ID,
                })

    findings.sort(key=lambda f: (0 if f["severity_hint"] == "critical" else 1,
                                 f["file"], f["line"]))
    return {"schema": SCHEMA, "mechanism": MECHANISM, "impact": IMPACT,
            "root": root, "storage_maps": sorted(storage_maps),
            "permissionless_grown": sorted(grown_permissionless),
            "findings": findings, "finding_count": len(findings)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root", help="Rust source tree (pallet/crate root) or a .rs file")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    rep = scan_root(args.root)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"[consensus-hook-unbounded-iteration/substrate] "
              f"storage_maps={rep['storage_maps']} "
              f"permissionless_grown={rep['permissionless_grown']} "
              f"findings={rep['finding_count']}")
        for f in rep["findings"]:
            print(f"  [{f['severity_hint'].upper()}] {f['file']}:{f['line']} "
                  f"{f['function']} :: .{f['iter']}({f['receiver']}) - {f['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
