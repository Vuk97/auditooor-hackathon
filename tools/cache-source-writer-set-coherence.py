#!/usr/bin/env python3
"""cache-source-writer-set-coherence.py  (A6) - CACHE/SOURCE writer-set coherence.

WHAT THIS TOOL DOES
===================
A6 is a GENERAL, language-agnostic-in-spirit (Solidity/EVM arm here) INVARIANT /
TRUST-ENFORCEMENT screen, not a specific bug shape. It enforces one private
invariant of any DERIVED-CACHE relationship:

  THE DELEGATED-AND-TRUSTED PROPERTY
    A CACHE storage location C is trusted by every reader to faithfully mirror /
    aggregate its SOURCE storage location S. Readers of C never re-derive from S;
    they trust C is fresh.

  THE PRIVATE INVARIANT (what makes that trust sound)
    writers(S)  is a subset of  writers(C)
    i.e. EVERY function that mutates the source ALSO refreshes the cache. If the
    two writer-SETS differ (source has M writers, cache has K writers, M != K),
    then some function in writers(S) \\ writers(C) mutates the source WITHOUT
    refreshing the cache -> a subsequent read of C is STALE.

  THE ATTACK (north-star: attack the invariant)
    Drive the un-paired source-writer, then read the now-stale cache. This is the
    single general shape that subsumes:
      * partial-flush  - an aggregate/total cache a member-writer forgot to bump,
      * VM-loader / stored-copy desync - a mirrored copy a mutator forgot to sync.

PAIRING MODES (how a (source, cache) pair is discovered - all NAME/STRUCTURE, never
an impact or a bug shape):
  affix-cache     C = cached<B>/last<B>/stored<B>/<B>Cache/<B>Cached/<B>Snapshot,
                  and <B> is itself a state variable  -> the stored-copy half.
  aggregate-cache C = total<B>/sum<B>/aggregate<B>/global<B>/accumulated<B>, and a
                  mapping/array state var matching <B> exists -> the partial-flush half.
  derived-assign  a scalar state var C is assigned `C = <expr containing state var S>`
                  somewhere (C mirrors S)               -> generic derived cache.

WRITER SET is computed with a bounded internal-call closure so a function that
refreshes the cache via a helper (`_syncCache()`) is credited, and with two
FP-GUARDS so the tool stays SILENT on benign code:
  * NET-NEUTRAL exclusion: a function that moves value BETWEEN keys of a mapping
    source (has both `S[a] += ..` and `S[b] -= ..`, e.g. an ERC20 transfer) does
    NOT change the aggregate, so it is NOT required to touch the total. Excluded
    from the source-writer set for aggregate-cache pairs.
  * constructor/initializer exclusion: initial-state setters establish both sides.

NO-AUTO-CREDIT / ADVISORY-FIRST: every emitted row carries verdict="needs-fuzz".
This tool never flips a gate, never resolves a unit, never fails closed. Hang it
on the completeness-matrix CACHE-COHERENCE / coupled-state axis.

DEDUP BOUNDARY: A6 is the SYNTACTIC WRITER-SET-MEMBERSHIP screen (cheap, no
delta/SSA reasoning). The SEMANTIC sum-conservation lane (state-coupling-graph
`conserved-with` / A13 cross-contract) owns proving sum(parts)==total via
same-delta dataflow; A6 aggregate-cache rows carry a dedup_note deferring the
delta proof there. A6's UNIQUE contribution is the affix-cache / derived-assign
(stored-copy) half, which the conservation lanes structurally do not model.

FAIL-OPEN: an unparseable file yields an empty hypotheses list + an accounting
record, exit 0.

Usage:
  python3 tools/cache-source-writer-set-coherence.py --workspace <ws> [--json]
  python3 tools/cache-source-writer-set-coherence.py --file <f.sol> [--json]   # test
  python3 tools/cache-source-writer-set-coherence.py --source <dir> [--json]   # test
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys

OUT_REL = os.path.join(".auditooor", "cache_source_writer_set_hypotheses.jsonl")
ACC_REL = os.path.join(".auditooor", "cache_source_writer_set_accounting.json")

# ------------------------------------------------------------------ pairing
# affix-cache: C carries a cache affix over a base name B; ordered longest-first
# so `cached`/`stored` win before a bare match. (prefix, suffix) - exactly one set.
_AFFIXES = (
    ("cached", ""), ("_cached", ""), ("stored", ""), ("snapshot", ""),
    ("", "Cache"), ("", "Cached"), ("", "Snapshot"), ("", "Stored"),
    ("last", ""),
)
_AGG_PREFIXES = ("total", "sum", "aggregate", "global", "accumulated")

_INIT_FN_HINTS = ("constructor", "initialize", "__init", "_init", "reinitialize")


def _lower_first(s: str) -> str:
    return s[:1].lower() + s[1:] if s else s


def _affix_base(name: str):
    """If `name` carries a cache affix, return its base (else None)."""
    for pre, suf in _AFFIXES:
        if pre and name.lower().startswith(pre.lower()) and len(name) > len(pre):
            return _lower_first(name[len(pre):])
        if suf and name.endswith(suf) and len(name) > len(suf):
            return name[: -len(suf)]
    return None


def _agg_base(name: str):
    """If `name` is an aggregate cache (total<B>...), return base B (else None)."""
    low = name.lower()
    for pre in _AGG_PREFIXES:
        if low.startswith(pre) and len(name) > len(pre):
            return _lower_first(name[len(pre):])
    return None


def _name_match(a: str, b: str) -> bool:
    """Loose singular/plural equality on identifiers (shares==share, x==xs)."""
    a, b = a.lower(), b.lower()
    if a == b:
        return True
    return a.rstrip("s") == b.rstrip("s") and abs(len(a) - len(b)) <= 1


# ------------------------------------------------------------------ parsing
_STATE_VAR = re.compile(
    r"^[ \t]*(mapping\s*\([^;{}]*?\)|u?int\d*|address|bool|bytes\d*)\s+"
    r"(?:public|internal|private)\s+(?:immutable\s+|constant\s+|override\s+)*"
    r"([A-Za-z_]\w*)\s*[;=]",
    re.M,
)


def parse_state_vars(src: str) -> dict:
    """name -> {'is_mapping': bool, 'immutable': bool}. Contract-level state vars
    only (require a visibility keyword; excludes locals)."""
    out = {}
    for m in _STATE_VAR.finditer(src):
        typ, name = m.group(1), m.group(2)
        line = m.group(0)
        out[name] = {
            "is_mapping": typ.strip().startswith("mapping")
            or "[]" in line,
            "immutable": "immutable" in line or "constant" in line,
        }
    return out


_FN_HEADER = re.compile(
    r"\b(function\s+([A-Za-z_]\w*)|constructor|receive\s*\(|fallback\s*\()",
)


def parse_functions(src: str):
    """Return list of {name, body, is_init}. Brace-matched bodies; skips
    interface/abstract fn declarations that end in `;`."""
    fns = []
    for m in _FN_HEADER.finditer(src):
        name = m.group(2) or (m.group(1).split("(")[0].strip())
        # find the first `{` after the header; if a `;` comes first it's a decl.
        i = m.end()
        depth = 0
        brace = src.find("{", i)
        semi = src.find(";", i)
        if brace == -1:
            continue
        if semi != -1 and semi < brace:
            continue  # declaration only (interface / abstract / modifier list)
        j = brace
        depth = 0
        while j < len(src):
            c = src[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body = src[brace + 1 : j]
        fns.append(
            {
                "name": name,
                "body": body,
                "is_init": any(h in name.lower() for h in _INIT_FN_HINTS),
            }
        )
    return fns


# assignment to a scalar V: V = / += / -= / *= / etc, V++, V--, delete V
def _writes_scalar(body: str, v: str) -> bool:
    if re.search(
        r"(?<![.\w])" + re.escape(v) + r"\s*(?:\+\+|--)", body
    ):
        return True
    if re.search(r"\bdelete\s+" + re.escape(v) + r"\b", body):
        return True
    # compound / plain assignment (not ==, !=, <=, >=)
    if re.search(
        r"(?<![.\w])" + re.escape(v)
        + r"\s*(?:\+=|-=|\*=|/=|%=|\|=|&=|\^=|<<=|>>=)",
        body,
    ):
        return True
    if re.search(
        r"(?<![.\w])" + re.escape(v) + r"\s*=(?!=)", body
    ):
        # exclude the `<= V` / `>= V` / `!= V` / `== V` comparison forms where V
        # is on the RHS: those never match the LHS anchor above, so plain `=` here
        # is an assignment. Still guard against `foo = bar == V`.
        return True
    return False


def _writes_mapping(body: str, v: str) -> bool:
    esc = re.escape(v)
    if re.search(esc + r"\s*\[[^\]]*\]\s*(?:=(?!=)|\+=|-=|\*=|/=|%=)", body):
        return True
    if re.search(r"\bdelete\s+" + esc + r"\s*\[", body):
        return True
    if re.search(esc + r"\s*\[[^\]]*\]\s*(?:\+\+|--)", body):
        return True
    return False


def _writes(body: str, v: str, is_mapping: bool) -> bool:
    return _writes_mapping(body, v) if is_mapping else _writes_scalar(body, v)


def _net_neutral_mapping(body: str, v: str) -> bool:
    """A function that moves value BETWEEN keys of mapping v (has both a += and a
    -= on v[..]) does not change the aggregate -> excluded from source writers."""
    esc = re.escape(v)
    inc = re.search(esc + r"\s*\[[^\]]*\]\s*\+=", body) or re.search(
        esc + r"\s*\[[^\]]*\]\s*=\s*[^;]*\+", body
    )
    dec = re.search(esc + r"\s*\[[^\]]*\]\s*-=", body) or re.search(
        esc + r"\s*\[[^\]]*\]\s*=\s*[^;]*-", body
    )
    return bool(inc and dec)


_COMPOUND = re.compile(
    r"\s*(?:\+=|-=|\*=|/=|%=|\|=|&=|\^=|<<=|>>=|\+\+|--)"
)


def _accumulated_anywhere(fns, v: str) -> bool:
    """True if scalar v is EVER mutated with a compound op / inc-dec. A genuine
    derived cache is OVERWRITTEN wholesale (`C = f(S)`); an independent
    accumulator uses `+=`/`-=`. This distinguishes a stored cache from a
    conservation BUCKET (two co-equal accumulators), killing the LiquidityPool
    totalValueInLp/totalValueOutOfLp FP class."""
    esc = re.escape(v)
    pat = re.compile(r"(?<![.\w])" + esc + _COMPOUND.pattern)
    return any(pat.search(f["body"]) for f in fns)


def _internal_callees(body: str, fn_names: set) -> set:
    out = set()
    for m in re.finditer(r"(?<![.\w])([A-Za-z_]\w*)\s*\(", body):
        nm = m.group(1)
        if nm in fn_names:
            out.add(nm)
    return out


def _writer_closure(fns, target, is_mapping, exclude_net_neutral):
    """Set of fn NAMES that write `target` directly OR transitively via an
    internal call (bounded 3 hops)."""
    names = {f["name"] for f in fns}
    by_name = {f["name"]: f for f in fns}
    direct = set()
    for f in fns:
        if _writes(f["body"], target, is_mapping):
            if exclude_net_neutral and is_mapping and _net_neutral_mapping(
                f["body"], target
            ):
                continue
            direct.add(f["name"])
    # transitive: a caller of a direct-writer is credited (it refreshes via helper)
    reach = set(direct)
    for _ in range(3):
        added = False
        for f in fns:
            if f["name"] in reach:
                continue
            if _internal_callees(f["body"], names) & reach:
                # only credit if the callee's write is the paired refresh, not a
                # net-neutral pass; the callee already passed that filter.
                reach.add(f["name"])
                added = True
        if not added:
            break
    return reach


# ------------------------------------------------------------------ pairing build
def _build_pairs(state_vars: dict, fns):
    """Return list of (source, cache, mode, source_is_mapping)."""
    pairs = []
    scalars = {n for n, i in state_vars.items() if not i["is_mapping"]}
    maps = {n for n, i in state_vars.items() if i["is_mapping"]}

    for c in list(state_vars):
        if state_vars[c]["immutable"]:
            continue  # a set-once immutable cache has no runtime writer-set

        # affix-cache: base is a state var (scalar or mapping)
        b = _affix_base(c)
        if b:
            for cand in list(scalars) + list(maps):
                if cand == c:
                    continue
                if _name_match(cand, b):
                    pairs.append((cand, c, "affix-cache",
                                  state_vars[cand]["is_mapping"]))
                    break

        # aggregate-cache: total<B> over a mapping/array B
        ab = _agg_base(c)
        if ab and not state_vars[c]["is_mapping"]:
            for mp in maps:
                if _name_match(mp, ab):
                    pairs.append((mp, c, "aggregate-cache", True))
                    break

    # derived-assign: scalar C assigned `C = <expr with state var S>`
    src_join = "\n".join(f["body"] for f in fns)
    for c in scalars:
        if state_vars[c]["immutable"]:
            continue
        if any(pr[1] == c for pr in pairs):
            continue  # already paired by name
        if _accumulated_anywhere(fns, c):
            continue  # accumulator/bucket, not an overwritten derived cache
        m = re.search(
            r"(?<![.\w])" + re.escape(c) + r"\s*=(?!=)\s*([^;]+);", src_join
        )
        if not m:
            continue
        rhs = m.group(1)
        for s in scalars | maps:
            if s == c:
                continue
            if re.search(r"(?<![.\w])" + re.escape(s) + r"(?![\w])", rhs):
                pairs.append((s, c, "derived-assign",
                              state_vars[s]["is_mapping"]))
                break
    return pairs


def writer_set_desync(source_writers: set, cache_writers: set) -> set:
    """CORE PREDICATE. The functions that mutate the source but do NOT refresh the
    cache. Non-empty == coherence broken. Neutralizing this (always {}) silences
    every finding -> the non-vacuity anchor."""
    return set(source_writers) - set(cache_writers)


# ------------------------------------------------------------------ analyze
def analyze_source(src: str, path: str = "<mem>"):
    hyps = []
    try:
        state_vars = parse_state_vars(src)
        fns = parse_functions(src)
    except Exception as exc:  # fail-open on any parse fault
        return [], {"status": "parse-error", "note": str(exc)[:120]}

    pairs = _build_pairs(state_vars, fns)
    non_init = [f for f in fns if not f["is_init"]]
    seen = set()
    for (source, cache, mode, src_is_map) in pairs:
        key = (source, cache)
        if key in seen:
            continue
        seen.add(key)
        exclude_nn = mode == "aggregate-cache"
        src_writers = _writer_closure(
            non_init, source, src_is_map, exclude_nn
        )
        cache_writers = _writer_closure(non_init, cache, False, False)
        if not src_writers or not cache_writers:
            continue  # need BOTH sides to have runtime writers to compare
        desync = writer_set_desync(src_writers, cache_writers)
        if not desync:
            continue  # coherent -> SILENT
        dn = (
            "A6 syntactic writer-set membership; SEMANTIC sum-conservation "
            "deferred to state-coupling-graph conserved-with"
            if mode == "aggregate-cache"
            else "A6 stored-copy/derived-cache staleness (conservation lanes "
            "do not model this affix/derived mirror)"
        )
        hyps.append(
            {
                "flag_kind": "cache-source-writer-set-desync",
                "file": path,
                "source": source,
                "cache": cache,
                "pairing_mode": mode,
                "source_writers": sorted(src_writers),
                "cache_writers": sorted(cache_writers),
                "desync_writers": sorted(desync),
                "M_source_writers": len(src_writers),
                "K_cache_writers": len(cache_writers),
                "verdict": "needs-fuzz",
                "attack_class": "cache-coherence-writer-set",
                "invariant": "writers(source) subset-of writers(cache)",
                "hacker_question": (
                    f"Which path writes `{source}` without refreshing `{cache}`, "
                    f"and what reads the now-stale `{cache}`?"
                ),
                "dedup_note": dn,
            }
        )
    acc = {
        "status": "ok",
        "state_vars": len(state_vars),
        "functions": len(fns),
        "pairs": len(pairs),
        "hypotheses": len(hyps),
    }
    return hyps, acc


def _iter_sol(root: pathlib.Path):
    skip = (
        "/lib/", "/test/", "forge-std", "/node_modules/", "/mocks/",
        "poc-tests", "chimera_harness", "chimera_harnesses", "/script/",
        "mutants/", "/dependencies/",
    )
    for p in root.rglob("*.sol"):
        s = str(p)
        if any(x in s for x in skip):
            continue
        low = s.lower()
        if "mock" in low or ".t.sol" in low or ".s.sol" in low:
            continue
        yield p


def analyze_path(target: pathlib.Path):
    hyps, files = [], 0
    if target.is_file():
        src = target.read_text(errors="ignore")
        h, _ = analyze_source(src, str(target))
        hyps.extend(h)
        files = 1
    else:
        for p in _iter_sol(target):
            try:
                src = p.read_text(errors="ignore")
            except Exception:
                continue
            h, _ = analyze_source(src, str(p))
            hyps.extend(h)
            files += 1
    acc = {
        "tool": "cache-source-writer-set-coherence",
        "status": "ok",
        "files_scanned": files,
        "hypotheses": len(hyps),
    }
    return hyps, acc


def _emit(base: pathlib.Path, hyps, acc, out=None):
    op = pathlib.Path(out) if out else (base / OUT_REL)
    op.parent.mkdir(parents=True, exist_ok=True)
    with open(op, "w") as f:
        for h in hyps:
            f.write(json.dumps(h) + "\n")
    ap = base / ACC_REL
    ap.parent.mkdir(parents=True, exist_ok=True)
    with open(ap, "w") as f:
        json.dump(acc, f, indent=2)


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--workspace")
    g.add_argument("--file")
    g.add_argument("--source")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    if args.workspace:
        ws = pathlib.Path(args.workspace)
        if not ws.is_dir():
            print(f"[err] workspace not found: {ws}", file=sys.stderr)
            sys.exit(1)
        # scan the ws source tree (ws itself; sub-src dirs picked up by rglob)
        hyps, acc = analyze_path(ws)
        base = ws
    elif args.file:
        tgt = pathlib.Path(args.file)
        hyps, acc = analyze_path(tgt)
        base = tgt.parent
    else:
        tgt = pathlib.Path(args.source)
        hyps, acc = analyze_path(tgt)
        base = tgt

    if not args.file:  # only persist sidecars for ws/source runs
        _emit(base, hyps, acc, args.out)

    if args.json:
        print(json.dumps({"accounting": acc, "hypotheses": hyps}))
    else:
        print(f"[ok] A6 cache-source-writer-set-coherence: {acc['status']}")
        print(f"     files scanned:        {acc.get('files_scanned', 1)}")
        print(f"     hypotheses (needs-fuzz): {acc['hypotheses']}")
        for h in hyps[:20]:
            print(
                f"       - {h['file']}: {h['source']} -> {h['cache']} "
                f"[{h['pairing_mode']}] desync={h['desync_writers']}"
            )


if __name__ == "__main__":
    main()
