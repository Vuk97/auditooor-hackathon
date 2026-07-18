#!/usr/bin/env python3
"""state-coupling-graph.py - build the State-Coupling Graph (SCG), the generalized
Aptos-class coupling-completeness dimension. See
reports/state_coupling_completeness_framework_design.md.

Tiering (R80 honesty):
  - SYNTACTIC baseline: reuse tools/coupled-state-completeness.py rows (flush-set /
    paired-stem / derived-from / co-indexed) -> one SCG edge each. Advisory PROMPT.
  - SEMANTIC-SSA overlay: when <ws>/.auditooor/dataflow_paths.jsonl exists (produced
    by dataflow-slice.py / go|rust|zk-dataflow.py), an edge whose BOTH cells are
    witnessed moving in the real def-use slice is upgraded to semantic-ssa + evidence.

This is P1 of the phased build: it grounds the regex dimension in the real polyglot
def-use infra without rebuilding it, and emits the frozen state_coupling_edge.v1
schema that the completeness-check / exploit-queue / completeness-matrix consume.

Usage:
  --workspace <ws> --emit        build SCG -> .auditooor/state_coupling_edges.jsonl
  --workspace <ws> --co-indexed  also include the opt-in co-indexed regex lane
  --file <f> --emit              (test) single file, print edges to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
import state_coupling_schema as scs  # noqa: E402  (sibling module)


def _load_module(name: str, filename: str):
    """Import a hyphenated sibling tool by path. MUST register in sys.modules BEFORE
    exec_module: a module that uses @dataclass resolves field types via
    sys.modules[cls.__module__].__dict__, which is None (-> AttributeError) if the
    module was never registered - a silent-import-failure trap under Python 3.14."""
    spec = importlib.util.spec_from_file_location(name, _HERE / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_csc = _load_module("csc", "coupled-state-completeness.py")
_df = _load_module("dataflow_schema", "dataflow_schema.py")

# regex set_kind -> SCG coupling kind
_KIND_MAP = {
    "flush-set": "flush-group",
    "aggregate-parity": "flush-group",
    "paired-stem": "paired-lifecycle",
    "derived-coupling": "derived-from",
    "co-indexed": "co-indexed",
    "conserved-with": "conserved-with",
    "ordering": "ordering",
}

# ordering-sequence roots: a derived-from over a monotonic on-chain counter is really
# an ordering coupling (version<->commit, nonce<->hash) - a writer that advances one
# sequence without the paired bump desyncs them (Sei tx-version<->commit shape).
_ORDERING_ROOTS = ("version", "nonce", "seq", "sequence", "commit", "epoch",
                   "round", "counter", "height", "checkpoint", "cowversion")


def _row_to_edge(row: dict, language: str) -> dict:
    kind = _KIND_MAP.get(row.get("set_kind"), "derived-from")
    mutates = row.get("mutates") or []
    omits = row.get("omits") or []
    # cell_b = the mutated source; cell_a = the omitted (derived/coupled) endpoint.
    cell_b = mutates[0] if mutates else "?"
    cell_a = omits[0] if omits else (
        [c for c in (row.get("set_members") or []) if c != cell_b] or ["?"])[0]
    wf, wl = row.get("writer_file", "?"), row.get("writer_line", 0)
    edge_id = hashlib.sha1(
        f"{wf}:{wl}:{kind}:{cell_a}:{cell_b}".encode()).hexdigest()[:12]
    violator = {
        "fn": row.get("writer_fn", "?"),
        "file": wf,
        "line": wl,
        "mutates": mutates,
        "omits": omits,
    }
    return scs.new_edge(
        edge_id=edge_id, language=language, kind=kind,
        cell_a=cell_a, cell_b=cell_b,
        writers_a=[], writers_b=[], violators=[violator],
        confidence="syntactic",
        evidence={"tier": "regex", "question": row.get("question", "")},
    )


def _language_of(rel: str) -> str:
    s = Path(rel).suffix.lower()
    return {".sol": "solidity", ".go": "go", ".rs": "rust",
            ".move": "move", ".circom": "circom"}.get(s, "unknown")


# P2a precision gate: path denylist (vendored / test / sim / tracer files whose
# "state" is fixtures, not the CUT). Reuses the coverage-denominator idea.
_DENY_PARTS = {"go-ethereum", "vendor", "node_modules", "third_party", "mock",
               "mocks", "test", "tests", "testdata", "tracers", "simulation",
               "sims", "examples", "example"}
_DENY_SUBSTR = ("blocksim", "cryptosim", "benchmark", "_test.", "fuzz_",
                "_mock", "mock_", ".t.sol", "generatechain")


def _is_denied(rel: str) -> bool:
    if not rel:
        return False
    parts = [p.lower() for p in Path(rel).parts]
    if any(p in _DENY_PARTS for p in parts):
        return True
    base = Path(rel).name.lower()
    return any(s in base for s in _DENY_SUBSTR)


def _storage_facts(ws: Path):
    """The AUTHORITATIVE persistent-state set + write sites, from the real def-use
    slice. A def-use engine emits a `via="storage"` hop ONLY when a value crosses
    functions THROUGH a storage cell - so a hop's from_var/to_var is proven
    persistent state (never a function-local, a parameter, or a value-receiver
    copy). Grounding BOTH coupled cells in this set subsumes every measured FP class
    (param 'operator', local 'operators', value-receiver 'Tokens', etc.) with one
    principled check instead of N per-language heuristics. Returns
    (storage_cells, cell_sites)."""
    cells: set[str] = set()
    sites: dict[str, list] = {}
    try:
        recs = _df.read_paths(str(ws), skip_degraded=True)
    except Exception:
        return cells, sites
    for r in recs:
        for h in (r.get("hops") or []):
            if h.get("via") == "storage":
                for v in (h.get("from_var"), h.get("to_var")):
                    if v:
                        v = str(v)
                        cells.add(v)
                        sites.setdefault(v, []).append(
                            (h.get("file"), h.get("line"), h.get("fn")))
    return cells, sites


def _norm_fn(f: str) -> str:
    """Normalize a function identifier to its BARE name so the dataflow slice's
    qualified name joins with VMF's bare `fn`. Handles BOTH:
      - Solidity `Contract.fn(argtypes)` -> `fn`
      - Go method `(*pkg/path.Keeper).Deposit(ctx,...)` -> `Deposit` (the Go SSA form
        starts with the parenthesised receiver, so a naive split('(')[0] yields '' and
        the bare-fn join silently fails for EVERY Go/Cosmos value-mover - measured on NUVA).
    Drops the receiver, the `(args)` signature, and any `Contract.`/`pkg.` qualifier."""
    if not f:
        return f
    s = str(f)
    if s.startswith("("):                # Go: (Recv).Method(args) -> take after the ")."
        idx = s.find(").")
        if idx >= 0:
            s = s[idx + 2:]
    s = s.split("(", 1)[0]               # drop the (arg,types) signature
    return s.rsplit(".", 1)[-1]          # drop the Contract./package. qualifier


# cosmos-sdk collections-INTERNAL type/var names that leak into sink.cell when the receiver
# walk lands on a collections wrapper/index rather than the keeper FIELD (measured on NUVA:
# refKeys/IndexedMap/keyset/m/Store noise mixed with real cells Vaults/Balances/Supply). A
# real persistent cell is an EXPORTED keeper field; drop collections type names + lowercase-
# first locals so the resolver grounds only genuine cells.
_COLLECTIONS_TYPE_CELL = frozenset({
    "Map", "IndexedMap", "KeySet", "Item", "Sequence", "Pair", "Triple", "Set",
    "Store", "KVStore", "BasicKVStore", "NoValue", "collectionSchemaCodec"})


def _is_noise_cell(cell: str) -> bool:
    """A sink.cell is NOISE (a collections wrapper/index/local, not a persistent field) if it
    is a collections-internal type name OR lowercase-first (a local var like m/keyset/refKeys,
    never an exported keeper field). Real cells are exported keeper fields (Vaults/Balances)."""
    c = str(cell)
    return (not c) or c in _COLLECTIONS_TYPE_CELL or (c[:1].islower())


# a TEMPORAL prefix (first/new/last/prev/_...) marks the SAME quantity at a different point in
# time (firstTotalAssets vs _totalAssets = totalAssets before/after), NOT a distinct coupled
# cell. A conserved-with PAIR of two temporal variants of one root is a snapshot/delta pair,
# not a must-move-together conservation (FP measured on morpho: firstTotalAssets<->_totalAssets).
_TEMPORAL_PREFIX = re.compile(
    r"^(?:first|new|last|prev|previous|cur|current|old|initial|final|pending|next|updated"
    r"|stored|cached|snapshot|orig|original)(?=[A-Z_])", re.I)


def _temporal_root(c: str) -> str:
    s = str(c).lstrip("_")
    s = _TEMPORAL_PREFIX.sub("", s)
    return s.lstrip("_").lower()


def _same_temporal_quantity(a: str, b: str) -> bool:
    """True when a and b are temporal variants of the SAME root quantity (a snapshot/delta
    pair, not a conservation). e.g. firstTotalAssets <-> _totalAssets -> both root=totalassets."""
    ra, rb = _temporal_root(a), _temporal_root(b)
    return bool(ra) and ra == rb and str(a) != str(b)


def _name_to_cell(ws: Path, stats: dict | None = None) -> dict[tuple[str, str], str]:
    """(fn, local_name) -> PERSISTENT storage cell, from the def-use slice.

    The conserved-with lane matches field names ACROSS functions to find a cross-
    function strict-subset writer (the Aptos partial-flush shape). But VMF's
    ledger_write_evidence often names FUNCTION-LOCAL temporaries (NUVA
    DedicatedVaultRouter._doDeposit writes locals receivedAmount/vaultShares/...),
    which are unique per function - so no other function ever writes "a subset of the
    same set" and the cross-function class STRUCTURALLY cannot fire even when a real
    partial-update path exists on the persistent ledger. Resolving each local to the
    persistent cell it flows INTO (via a `via='storage'` hop) lets the match run over
    persistent-cell identity, so two functions that both write cell C now collide.

    A local L in fn F resolves to cell C when a slice path sourced at (F, L) - or a hop
    reading L in F - carries a storage hop writing C. Best-effort: unmapped names fall
    through to their raw identity (the pre-slice behaviour), so a workspace with no
    slice is byte-identical to before.

    FN-NAME NORMALIZATION (task_ba16b499): the dataflow slice names functions with the
    FULLY-QUALIFIED signature (`DedicatedVaultRouter._doDeposit(uint256,...)`) while VMF
    ledger_write_evidence carries the BARE name (`_doDeposit`), so an exact (fn, name)
    join finds NOTHING (NUVA measured slice_resolution_pairs=0 despite the value-movers
    being present in the slice under their qualified names). Register a SECOND key under
    the bare fn so a bare-named lookup resolves - but ONLY when the bare key is
    UNAMBIGUOUS (same (bareFn, name) never maps to two different cells across contracts);
    an ambiguous bare key is disabled so a two-contract name collision never mis-binds.

    `stats` (optional out-dict) characterizes WHY a 0-pair result occurred, so the DONE
    gate can tell a BROKEN resolver from an INAPPLICABLE one (anti-silent-suppression):
      - storage_hops_seen: total `via=storage` hops in the slice
      - identity_hops: hops with from_var==to_var (a param/config `x=x` write - nothing to
        resolve; a local never flows to a DISTINCT persistent cell)
      - distinct_flow_hops: hops with from_var!=to_var (the only ones a resolution can use)
    A 0 with storage_hops_seen>0 and distinct_flow_hops==0 is 0-INAPPLICABLE (the slice has
    no local->cell flow), NOT 0-broken. Measured on NUVA: 861 storage hops, ALL identity."""
    m: dict[tuple[str, str], str] = {}
    bare: dict[tuple[str, str], str | None] = {}  # (bareFn,name)->cell, None=ambiguous
    if stats is not None:
        stats.setdefault("storage_hops_seen", 0)
        stats.setdefault("identity_hops", 0)
        stats.setdefault("distinct_flow_hops", 0)
        stats.setdefault("go_sink_cells", 0)
        stats.setdefault("go_state_write_sinks_seen", 0)
    try:
        recs = _df.read_paths(str(ws), skip_degraded=True)
    except Exception:
        return m
    for r in recs:
        # Go representation: cosmos-sdk collections persist state via a terminal
        # `state-write` SINK (`k.Vaults.Set(...)`), NOT a `via=storage` hop (the Solidity
        # form). go-dataflow emits the persistent cell as sink.cell (the receiver collection
        # FIELD name, gated on looksLikeCollections so it is a real cell not keeper/store
        # noise). Consume it so Go value-movers resolve to the cell they write - WITHOUT this
        # the resolver is BLIND to every cosmos-sdk storage write (measured NUVA: 603+
        # state-write sinks, 0 via=storage hops). Generic to every Go/Cosmos workspace;
        # Solidity is unaffected (its writes come through the via=storage branch below).
        sink = r.get("sink") or {}
        if sink.get("kind") == "state-write" and r.get("language") == "go" and stats is not None:
            # count EVERY Go state-write sink (with or without cell) so a degraded/old-binary
            # feeder - state-write sinks present but NONE carry sink.cell - is distinguishable
            # from a Sol ws that legitimately has 0 Go sinks. Root-caused on NUVA 2026-07-08:
            # GOPROXY=off blocked fetching the go.work-pinned go1.25.8, so the go arm emitted
            # 35 state-write sinks with 0 cells (vs 686/464 under the pinned toolchain).
            stats["go_state_write_sinks_seen"] = stats.get("go_state_write_sinks_seen", 0) + 1
        if sink.get("kind") == "state-write" and sink.get("cell") and not _is_noise_cell(sink["cell"]):
            scell = str(sink["cell"])
            sfn = sink.get("fn")
            if stats is not None:
                stats["storage_hops_seen"] += 1
                stats["distinct_flow_hops"] += 1
                stats["go_sink_cells"] = stats.get("go_sink_cells", 0) + 1
            src0 = r.get("source") or {}
            cands0: list[tuple] = [(sfn, src0.get("var"))]
            for h in (r.get("hops") or []):
                cands0.append((h.get("fn") or sfn, h.get("from_var")))
                cands0.append((h.get("fn") or sfn, h.get("to_var")))
            for fn, name in cands0:
                if fn and name and str(name) != scell:
                    m.setdefault((str(fn), str(name)), scell)
                    bk = (_norm_fn(str(fn)), str(name))
                    if bk in bare and bare[bk] != scell:
                        bare[bk] = None
                    else:
                        bare.setdefault(bk, scell)
            continue
        storage_hops = [h for h in (r.get("hops") or []) if h.get("via") == "storage"]
        if not storage_hops:
            continue
        if stats is not None:
            for h in storage_hops:
                stats["storage_hops_seen"] += 1
                if str(h.get("from_var") or "") == str(h.get("to_var") or ""):
                    stats["identity_hops"] += 1
                else:
                    stats["distinct_flow_hops"] += 1
        # the persistent cell this path lands on (prefer the written to_var).
        cell = None
        for h in storage_hops:
            cell = h.get("to_var") or h.get("from_var") or cell
        if not cell:
            continue
        cell = str(cell)
        src = r.get("source") or {}
        # register the local names seen upstream of the storage write, per their fn.
        cands: list[tuple] = [(src.get("fn"), src.get("var"))]
        for h in (r.get("hops") or []):
            cands.append((h.get("fn"), h.get("from_var")))
            cands.append((h.get("fn"), h.get("to_var")))
        for fn, name in cands:
            if fn and name and str(name) != cell:
                m.setdefault((str(fn), str(name)), cell)
                bk = (_norm_fn(str(fn)), str(name))
                if bk in bare and bare[bk] != cell:
                    bare[bk] = None  # collision across contracts -> disable this bare key
                else:
                    bare.setdefault(bk, cell)
    # merge the UNAMBIGUOUS bare keys (never overwrite an exact qualified key).
    for bk, c in bare.items():
        if c is not None:
            m.setdefault(bk, c)
    return m


_RATE_SUFFIX = ("bps", "bips", "rate", "ratio", "pct", "percent", "factor",
                "multiplier", "weight", "decimals")


def _is_rate_field(f: str) -> bool:
    fl = f.lower()
    return any(fl.endswith(s) or s in fl for s in _RATE_SUFFIX)


# a BOUND/limit (supplyCap / maxAssets / minShares / borrowLimit) is a config ceiling, NOT
# a conserved balance - pairing it into a conservation set is a FP (measured on morpho
# supplyCap<->shares, strata maxAssets/maxShares). camelCase-aware so it drops maxAssets /
# supplyCap but NOT the genuine value fields `capital` (not max/min-prefixed, not *Cap
# suffix) or `minted` (min not followed by an UPPERCASE letter).
_BOUND_RE = re.compile(r"^(?:max|min)[A-Z]|(?:Cap|Limit|Ceiling|Floor|Threshold|Bound)$")


def _is_bound_field(f: str) -> bool:
    return bool(_BOUND_RE.search(str(f)))


# a PRICE / oracle-quote (collateralPrice / oraclePrice / sharePrice) is a per-unit
# exchange rate, NOT a conserved balance - pairing it into a conservation set is a FP
# (measured on morpho: collateralPrice<->badDebtAssets/repaidAssets/position, 6/51).
# endswith-precise (NOT substring) so it drops *Price but keeps `pricedAssets` /
# `pricingBuffer` (amounts valued AT a price, which ARE conserved quantities).
def _is_price_field(f: str) -> bool:
    return str(f).lower().endswith("price")


# a conserved-with set is a VALUE/BALANCE obligation. Exclude config/handle fields
# (addresses) and delta-snapshot locals (balanceBefore/After) - they are not conserved
# quantities. Measured on NUVA: shareToken<->crossChainVault etc. were config FPs.
def _is_addr_or_snapshot_field(f: str) -> bool:
    fl = f.lower()
    return (fl.endswith("address") or fl.endswith("before") or fl.endswith("after")
            or fl.endswith("addr") or fl.endswith("recipient") or fl.endswith("owner")
            # timestamp / block-height snapshot fields are not a conserved VALUE amount:
            # a member value delta co-written with a lastUpdate/timestamp bump is not a
            # Sigma-conservation pair (guards the co-accumulation tier FP).
            or "timestamp" in fl or "lastupdate" in fl or fl.endswith("time")
            or fl.endswith("blocknumber") or fl.endswith("blocknum"))


# a conserved-with cell is a scalar VALUE/amount. On cosmos-Go, VMF's ledger fields
# are often STORE/COLLECTION type names (VaultAccount, VaultLookup, feeTimeoutQueue),
# not conserved amounts - measured as the NUVA FP class. Exclude structural-container
# names. Solidity value fields (amountToReserve, reserveNav, shares, suppliedAssets)
# are lowercase -> the lowercase branch is byte-unchanged.
_NONVALUE_SUFFIX = ("lookup", "queue", "registry", "table", "store", "cache")

# PascalCase (Go-exported) container/collection/handle/keeper/config TYPE-shaped suffixes:
# a NONVALUE cell name. Applied ONLY to an uppercase-first name, so the lowercase branch
# (Solidity + Go-local value fields) stays byte-identical to the prior behavior. This is the
# FIX for the flagship co-write arm: the prior code dropped EVERY PascalCase name, which
# wrongly excluded genuine cosmos struct VALUE fields written together in one fn (Balance /
# Supply / TotalShares / VaultShares / Reserve), so state_coupling_edges emitted 0 on every
# Go target despite 43 (sei) / 3 (axelar) multi-field value-movers. Now a PascalCase VALUE
# field survives; only a container/type-suffixed or exact-type-named PascalCase is dropped.
_NONVALUE_PASCAL_SUFFIX = (
    "Lookup", "Queue", "Registry", "Table", "Store", "Cache", "Keeper", "Manager",
    "Index", "Map", "Set", "Account", "Params", "Config", "Schema", "Codec",
    "Iterator", "Router", "Handler", "Module")
# exact structural/collections TYPE names (never a conserved value cell even though
# PascalCase) - mirrors _COLLECTIONS_TYPE_CELL for the value-field lane.
_NONVALUE_TYPE_NAMES = frozenset({
    "Map", "IndexedMap", "KeySet", "Item", "Sequence", "Pair", "Triple", "Set",
    "Store", "KVStore", "BasicKVStore", "NoValue", "Keeper", "Params", "Config",
    "Schema", "Codec", "Iterator", "Prefix", "Header", "Context", "State"})


def _is_nonvalue_field(f: str) -> bool:
    if not f:
        return True
    if f[:1].isupper():
        # PascalCase: NONVALUE only if an exact structural type name or a container/type
        # suffix; a genuine value field (Balance / Supply / TotalShares) survives.
        return f in _NONVALUE_TYPE_NAMES or f.endswith(_NONVALUE_PASCAL_SUFFIX)
    fl = f.lower()
    return any(fl.endswith(s) for s in _NONVALUE_SUFFIX)


# config / factory / lifecycle functions re-point handles; they are NOT value-
# conservation sources. Surgical prefixes/needles (do NOT match strata's real
# updateAccountingInner / reduceReserve / accrueFee / mint / withdraw).
_CONFIG_FN_RE = re.compile(r"^(initialize|register|migrate|deploy|create)", re.I)


def _is_config_fn(name: str) -> bool:
    return bool(_CONFIG_FN_RE.match(name or "")) or "config" in (name or "").lower()


_FN_DEF_LINE_CACHE: dict = {}


def _fn_def_line(ws: Path, rel: str, fn: str) -> int:
    """Resolve a function's definition line from source (VMF carries no line, so a
    violator would otherwise cite <file>:0 and be un-actionable)."""
    key = (str(ws), rel)
    lines = _FN_DEF_LINE_CACHE.get(key)
    if lines is None:
        try:
            lines = (ws / rel).read_text(errors="replace").splitlines()
        except OSError:
            lines = []
        _FN_DEF_LINE_CACHE[key] = lines
    pat = re.compile(r"\b(?:function|func|fn)\b[^\n]*\b" + re.escape(fn) + r"\b")
    for i, ln in enumerate(lines, 1):
        if pat.search(ln) or re.search(r"\b" + re.escape(fn) + r"\s*\(", ln):
            return i
    return 0


_GO_PERSIST_WRITE_RE = re.compile(r"\.\s*(?:Set|Remove|Delete)\s*\(")
_GO_SETTER_WRAPPER_RE = re.compile(r"\.\s*Set([A-Z]\w*)\s*\(")
_GO_ERR_RETURN_RE = re.compile(r"\breturn\b[^\n]*(?:,\s*err\b|\berr\b|fmt\.Errorf|errors\.New)")


def _go_persist_write_lines(blines: list[str], cells) -> list[int]:
    """Line indices that PERSIST state for the conserved set `cells`. A persist is EITHER a
    bare cosmos-collections call (`.Set(` / `.Remove(` / `.Delete(`) OR a keeper SETTER-WRAPPER
    `.Set<Suffix>(` whose Suffix matches a conserved-set cell (NUVA persists via wrappers like
    SetVaultShares, not bare collection calls - mutation-proven 2026-07-09 that a bare-only
    match is BLIND to a partial-flush in NUVA's real code shape). The suffix<->cell match keeps
    this from firing on unrelated geth-style setters (SetBalance/SetNonce) unless that cell is
    itself a surviving conserved coupled cell."""
    cell_toks = {str(c).lower() for c in cells}
    out: list[int] = []
    for i, l in enumerate(blines):
        if _GO_PERSIST_WRITE_RE.search(l):
            out.append(i)
            continue
        for m in _GO_SETTER_WRAPPER_RE.finditer(l):
            suf = m.group(1).lower()
            if any(suf == t or suf in t or t in suf for t in cell_toks):
                out.append(i)
                break
    return out


def _go_fn_body(ws: Path, rel: str, fn: str) -> str:
    """Return the source body of a Go fn (brace-balanced from its def line). Bounded."""
    start = _fn_def_line(ws, rel, fn)
    if start <= 0:
        return ""
    try:
        lines = (ws / rel).read_text(errors="replace").splitlines()
    except OSError:
        return ""
    out, depth, started = [], 0, False
    for ln in lines[start - 1:]:
        out.append(ln)
        depth += ln.count("{") - ln.count("}")
        if "{" in ln:
            started = True
        if started and depth <= 0:
            break
        if len(out) > 400:
            break
    return "\n".join(out)


def _flush_group_edges(ws: Path, cands: list, field_writers: dict) -> list[dict]:
    """FLUSH-GROUP (semantic, Go/Cosmos): a fn writing 2+ COUPLED persistent cells where a
    fallible error-return sits BETWEEN the first and last write and the writes are NOT wrapped
    in the atomic CacheContext+write() idiom -> a failure leaves a PARTIAL commit (partial
    flush). Anchored on NUVA reconcile.go (which uses CacheContext+write() correctly ->
    NEGATIVE). This is the intra-fn must-commit-together shape, complementing conserved-with's
    cross-fn subset-writer. Go-only by nature: Solidity reverts atomically. Advisory-first."""
    edges = []
    for S, sfile, sfn in cands:
        body = _go_fn_body(ws, sfile, sfn)
        if not body:
            continue
        if "CacheContext" in body and "write" in body.lower():
            continue  # atomic-commit idiom -> partial-flush impossible (cited-NEGATIVE)
        blines = body.splitlines()
        writes = _go_persist_write_lines(blines, S)
        errs = [i for i, l in enumerate(blines) if _GO_ERR_RETURN_RE.search(l)]
        if len(writes) >= 2 and any(writes[0] < e < writes[-1] for e in errs):
            cells = sorted(S)
            sid = hashlib.sha1(f"flush:{sfn}:{cells}".encode()).hexdigest()[:12]
            e = scs.new_edge(
                edge_id=sid, language="go", kind="flush-group",
                cell_a=cells[0], cell_b=cells[1],
                writers_a=sorted(field_writers.get(cells[0], set())),
                writers_b=sorted(field_writers.get(cells[1], set())),
                violators=[{"fn": sfn, "file": sfile,
                            "line": _fn_def_line(ws, sfile, sfn), "mutates": cells, "omits": []}],
                confidence="semantic-ssa",
                evidence={"grounding": "vmf+source-atomicity", "tier": "partial-flush",
                          "non_atomic": True, "error_return_between_writes": True,
                          "conserved_set": cells, "promotable": True,
                          "persistent_state": True, "slice_present": True})
            edges.append(e)
    return edges


# ORDERING (semantic, Solidity): a fn writes two COUPLED persistent cells with an EXTERNAL
# CALL textually BETWEEN the two writes and NO nonReentrant guard -> a reentrant callee
# observes the coupled invariant TRANSIENTLY half-updated (cellA written, cellB not yet), the
# classic reentrancy-on-a-coupled-invariant. Anchored on corpus tier-2 INV-ORD-001 ("W1,W2
# where W2 depends on W1 committed MUST have no intervening external call"), INV-ORD-005 (CEI),
# INV-BRIDGE-003 (consume-before-call). Solidity-specific: it is the reentrancy window that
# makes the ordering exploitable (Cosmos-Go is not reentrant in this sense -> flush-group is
# its analog). Distinct from generic CEI detectors: this fires ONLY when the two writes are a
# CONSERVED/coupled set, so the transient break is a real invariant violation not just a write.
_SOL_EXT_CALL_RE = re.compile(
    r"\.\s*(?:call|delegatecall)\s*[{(]"
    r"|\.\s*(?:transfer|send|sendValue|safeTransfer|safeTransferFrom|safeMint"
    r"|safeTransferETH|functionCall|onERC721Received|onERC1155Received)\s*\(")
_SOL_NONREENTRANT_RE = re.compile(r"\bnonReentrant\b")


def _sol_cell_writes(blines: list[str], cell: str) -> list[int]:
    """Line indices where `cell` is assigned (SSTORE): `cell =`, `cell[..] =`, `cell += ...`
    (not `==`/`<=`/`>=`)."""
    rx = re.compile(r"(?<![.\w])" + re.escape(cell) + r"\b\s*(?:\[[^\]]*\])*\s*(?<![=!<>])[-+*/]?=(?!=)")
    return [i for i, l in enumerate(blines) if rx.search(l)]


# a Solidity type prefix on a `<type> cell = ...` line marks a LOCAL declaration, not an
# SSTORE. Covers value types, bytesNN/uintNN/intNN, arrays, and a leading Capitalized type
# (contract/struct/enum) or `memory`/`storage`/`calldata` data-location keyword.
_SOL_LOCAL_DECL_TMPL = (
    r"(?:^|[;{]|\breturns?\b)\s*(?:address|bool|string|bytes\d*|uint\d*|int\d*"
    r"|mapping\b|[A-Z]\w*)(?:\s*\[[^\]]*\])?\s+(?:memory\s+|storage\s+|calldata\s+)?__CELL__\b")


def _sol_cell_is_local(header: str, body: str, cell: str) -> bool:
    """True iff `cell` is a function-LOCAL (param, named return, or an in-body typed
    declaration) rather than a persistent storage cell. The ordering detector uses VMF field
    names, which capture named returns / locals that merely LOOK like coupled cells (measured
    FP on etherfi LiquidRefer.deposit: `address vault = teller.vault()` local + `shares` named
    return - neither is storage, so no reentrancy-observable coupled invariant exists). Same
    local-vs-storage FP class the coupled-state regex tool drained earlier."""
    # param or named-return in the header (between the fn name and the body brace)
    if re.search(r"(?<![.\w])" + re.escape(cell) + r"\b", header or ""):
        return True
    # a typed local declaration anywhere in the body
    if re.search(_SOL_LOCAL_DECL_TMPL.replace("__CELL__", re.escape(cell)), body or ""):
        return True
    return False


def _sol_fn_header_body(src: str, fn: str) -> tuple[str, str]:
    """(header, body) for a Solidity fn: header = signature text up to the opening brace (holds
    modifiers like nonReentrant); body via the shared _csc extractor."""
    body = ""
    for n, _ln, b in _csc._functions(src):
        if n == fn:
            body = b
            break
    if not body:
        return "", ""
    m = re.search(r"\bfunction\s+" + re.escape(fn) + r"\b", src)
    if not m:
        return "", body
    brace = src.find("{", m.end())
    return (src[m.start():brace] if brace >= 0 else ""), body


def _ordering_group_edges(ws: Path, cands: list, field_writers: dict) -> list[dict]:
    """See _SOL_EXT_CALL_RE above. For each Solidity conserved candidate set (2+ coupled
    persistent cells written in one fn), emit a semantic-ssa `ordering` edge when an external
    call sits BETWEEN the earliest and latest coupled-cell write and the fn is NOT nonReentrant.
    Advisory-first; the reentrancy window is the exploit primitive."""
    edges = []
    for S, sfile, sfn in cands:
        cells = sorted(S)
        if len(cells) < 2:
            continue
        fp = ws / sfile
        if not fp.is_file():
            continue
        header, body = _sol_fn_header_body(fp.read_text(errors="replace"), sfn)
        if not body:
            continue
        if _SOL_NONREENTRANT_RE.search(header):
            continue  # reentrancy impossible -> ordering window closed (cited-NEGATIVE)
        # both coupled cells must be PERSISTENT STORAGE - a local/param/named-return that only
        # looks like a coupled cell has no cross-tx invariant a reentrant callee can observe
        # (etherfi LiquidRefer FP drain 2026-07-08).
        if _sol_cell_is_local(header, body, cells[0]) or _sol_cell_is_local(header, body, cells[1]):
            continue
        blines = body.splitlines()
        wa = _sol_cell_writes(blines, cells[0])
        wb = _sol_cell_writes(blines, cells[1])
        if not (wa and wb):
            continue
        calls = [i for i, l in enumerate(blines) if _SOL_EXT_CALL_RE.search(l)]
        first, last = min(wa + wb), max(wa + wb)
        if any(first < c < last for c in calls):
            sid = hashlib.sha1(f"ordering:{sfn}:{cells}".encode()).hexdigest()[:12]
            edges.append(scs.new_edge(
                edge_id=sid, language="solidity", kind="ordering",
                cell_a=cells[0], cell_b=cells[1],
                writers_a=sorted(field_writers.get(cells[0], set())),
                writers_b=sorted(field_writers.get(cells[1], set())),
                violators=[{"fn": sfn, "file": sfile,
                            "line": _fn_def_line(ws, sfile, sfn), "mutates": cells, "omits": []}],
                confidence="semantic-ssa",
                evidence={"grounding": "vmf+source-ordering",
                          "tier": "reentrancy-ordering-coupled-writes",
                          "external_call_between_coupled_writes": True,
                          "conserved_set": cells, "promotable": True,
                          "persistent_state": True, "slice_present": True}))
    return edges


# INTERRUPTION (Solidity, advisory + needs-fuzz): a two-phase request/cooldown lifecycle
# where a coupled RECORD set S is SPLIT across >=2 functions. Phase-1 CREATES a pending/
# request/cooldown-named record (a `.push(`/struct-store into a request array); the paired
# SETTLEMENT (a `.pop()`/`delete` of that record + the external asset release) lives ONLY in
# a SEPARATE finalize/cancel/claim body. NO single fn both creates AND settles the record, so
# if the phase-2 leg is unreachable/blocked the created record + custodied asset are stranded
# (partial-update freeze). This is the CROSS-fn / cross-tx split.
#
# DEDUP / FP-GUARD (A1 boundary): flush-group is the INTRA-fn shape (Go, 2 coupled cells both
# written in ONE body with an error-return between). Interruption ONLY fires when the create
# and the settle are in DIFFERENT bodies (no atomic fn) - if any single fn both pushes AND
# pops/deletes the record it is an atomic recovery, NOT an interruption (and is the flush-
# group-shaped intra-fn case), so it is EXCLUDED. Scalar accumulators never match (create is
# a record `.push(` only) so conserved-with / co-accumulation surfaces are not re-derived.
# Proving the freeze terminal needs negative-space reachability we only partly have ->
# verdict='needs-fuzz' (NO auto-credit), advisory-first behind SCG_INTERRUPTION (OFF default).
_PENDING_CELL_RE = re.compile(
    r"request|pending|cooldown|unlock|unstake|withdraw|redeem|queue|claimable|escrow", re.I)
_PHASE1_NAME_RE = re.compile(
    r"request|initiate|start|begin|queue|open|create|enter|cooldown|lock|deposit|stake", re.I)


def _sol_named_fns(src: str):
    """Yield (name, body) for each Solidity `function <name>(...) ... { body }`. Uses the
    `function` keyword so it is robust to MULTI-LINE signatures (which _csc._functions, a
    per-line matcher, mis-parses - it swallowed requestRedeem into the mapping decl on strata)
    and never mistakes a state-var/mapping declaration for a function."""
    for m in re.finditer(r"\bfunction\s+([A-Za-z_]\w*)\s*\([^{;]*\{", src):
        i = src.find("{", m.end() - 1)
        if i < 0:
            continue
        depth, j = 0, i
        while j < len(src):
            c = src[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    yield m.group(1), src[i:j + 1]
                    break
            j += 1


def _sol_record_ops(body: str, cell: str) -> tuple[bool, bool]:
    """(creates, settles) for `cell` in a Solidity fn body. Handles the storage-alias idiom
    `T[] storage a = cell[..];  a.push(..) / a.pop() / delete a`. create = a record PUSH;
    settle = a `.pop()` or `delete` of the record. Both direct (`cell.push`) and aliased."""
    names = {cell}
    for m in re.finditer(r"storage\s+(\w+)\s*=\s*" + re.escape(cell) + r"\b", body):
        names.add(m.group(1))
    alt = "|".join(re.escape(n) for n in names)
    creates = bool(re.search(r"(?<![.\w])(?:" + alt + r")\b\s*(?:\[[^\]]*\])*\s*\.\s*push\s*\(", body))
    settles = bool(
        re.search(r"(?<![.\w])(?:" + alt + r")\b\s*(?:\[[^\]]*\])*\s*\.\s*pop\s*\(", body)
        or re.search(r"\bdelete\s+(?:" + alt + r")\b", body))
    return creates, settles


def _interruption_edges(ws: Path, flush_edges: list[dict] | None = None) -> list[dict]:
    """See the INTERRUPTION header above. One advisory `interruption` edge per (file, pending
    cell) whose CREATE and SETTLE are split across distinct fns with NO atomic fn writing both.
    verdict='needs-fuzz' (NO auto-credit). DEDUP: emitted hits are dropped when a flush-group
    edge already covers the same (file, fn) - dedup vs the named detector, not a re-derive."""
    edges: list[dict] = []
    # DEDUP set vs the existing flush-group detector (A1: dedup emitted hits, do NOT re-derive
    # the covered_by signal). flush-group is Go/intra-fn so real collision is nil, but honor it.
    flush_cover: set[tuple] = set()
    for fe in (flush_edges or []):
        for v in fe.get("violators", []):
            flush_cover.add((v.get("file"), v.get("fn")))
    svars = _sol_state_var_names(ws)
    pending = {v for v in svars if _PENDING_CELL_RE.search(v)}
    if not pending:
        return edges
    for rel in _csc._load_inscope_files(ws):
        if _language_of(rel) != "solidity" or _is_denied(rel):
            continue
        fp = ws / rel
        if not fp.is_file():
            continue
        src = fp.read_text(errors="replace")
        fns = [(n, 0, b) for n, b in _sol_named_fns(src)]
        for cell in sorted(pending):
            if cell not in src:
                continue
            creators, settlers, atomic = [], [], []
            for name, _ln, body in fns:
                c, s = _sol_record_ops(body, cell)
                if c and s:
                    atomic.append(name)
                elif c:
                    creators.append(name)
                elif s:
                    settlers.append(name)
            # FIRE only on the CROSS-fn split: a create fn AND a settle fn exist, in DIFFERENT
            # bodies, with NO atomic fn (the FP-guard + flush-group boundary). Anchor phase-1
            # to a request/initiate-shaped creator name to hold FP down.
            if atomic or not creators or not settlers:
                continue
            phase1 = [n for n in creators if _PHASE1_NAME_RE.search(n)]
            if not phase1:
                continue
            if any((rel, n) in flush_cover for n in phase1):
                continue  # covered by flush-group already
            cells = [cell, "custody:" + cell]
            sid = hashlib.sha1(f"interruption:{rel}:{cell}".encode()).hexdigest()[:12]
            edges.append(scs.new_edge(
                edge_id=sid, language="solidity", kind="interruption",
                cell_a=cells[0], cell_b=cells[1],
                writers_a=sorted(set(creators + settlers + atomic)),
                writers_b=sorted(set(phase1)),
                violators=[{"fn": n, "file": rel, "line": _fn_def_line(ws, rel, n),
                            "mutates": [cell], "omits": ["settle:" + cell]} for n in sorted(phase1)],
                confidence="syntactic",
                evidence={"grounding": "source-two-phase-split", "tier": "interruption",
                          "verdict": "needs-fuzz", "advisory": True, "auto_credit": False,
                          "cross_fn_split": True, "no_atomic_writer": True,
                          "phase1_creators": sorted(phase1), "settlers": sorted(settlers),
                          "note": "phase-2 settle in a SEPARATE body; freeze-terminal needs "
                                  "negative-space reachability (fuzz) - NOT auto-credited"}))
    return edges


_SOL_STATE_VAR_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;{}]*\)|address|bool|string|bytes\d*|uint\d*|int\d*|[A-Z]\w*)"
    r"(?:\[[^\]]*\])?\s+(?:public\s+|private\s+|internal\s+|constant\s+|immutable\s+"
    r"|override\s+)*([a-z_]\w*)\s*[;=]", re.M)
_SOL_SVAR_CACHE: dict = {}


def _sol_fn_body_spans(src: str) -> list[tuple[int, int]]:
    spans = []
    for m in re.finditer(r"\bfunction\b[^{;]*\{", src):
        i = src.find("{", m.start())
        depth, j = 0, i
        while j < len(src):
            c = src[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    spans.append((i, j))
                    break
            j += 1
    return spans


def _sol_state_var_names(ws: Path) -> set:
    """Contract-level STATE VARIABLE names across the ws's Solidity sources (declarations
    OUTSIDE any function body). A conserved-with cell that is NOT a declared state var is a
    function-LOCAL (snapshot/delta/temp), never a conserved persistent quantity - the
    dominant conserved-with FP measured 2026-07-08 (87 promotable edges across 7 ws, ALL
    local-name-fallback; only 10 had both cells storage-backed). Used to gate promotable."""
    key = str(ws)
    if key in _SOL_SVAR_CACHE:
        return _SOL_SVAR_CACHE[key]
    names: set = set()
    try:
        for f in ws.rglob("*.sol"):
            if _is_denied(str(f.relative_to(ws)) if str(f).startswith(str(ws)) else str(f)):
                continue
            try:
                src = f.read_text(errors="replace")
            except OSError:
                continue
            spans = _sol_fn_body_spans(src)
            for m in _SOL_STATE_VAR_RE.finditer(src):
                if not any(a < m.start() < b for a, b in spans):
                    names.add(m.group(1))
    except OSError:
        pass
    _SOL_SVAR_CACHE[key] = names
    return names


def _internal_cell_promotable(ws: Path, cell: str, lang: str) -> bool:
    """Gate the PROMOTABLE flag of an edge on its INTERNAL cell being persistent storage.
    Solidity: the cell must be a declared contract-level state variable - a function-LOCAL
    (`uint256 amountForShares = pool.amountForShare(...)`) is NOT a conserved persistent
    quantity (measured FP: etherfi cross-domain edges keyed on locals amountForShares /
    eEthShares). Only gate when .sol source is scannable; Go/other keep prior behavior (Go
    struct fields are PascalCase, grounded via VMF/slice, e.g. NUVA TotalShares)."""
    if lang != "solidity":
        return True
    # gate only when .sol source is scannable (real source present); a VMF-only fixture with
    # no sources cannot be judged -> do not demote. An empty state-var set WITH sol sources
    # present is authoritative (the cell is genuinely not a contract state var -> local).
    try:
        has_sol = any(True for _ in ws.rglob("*.sol"))
    except OSError:
        has_sol = False
    if not has_sol:
        return True
    return cell in _sol_state_var_names(ws)


def _writers_from_sites(cell: str, sites: dict) -> list[str]:
    """Def-use-grounded writer set for a cell = the functions the storage hops
    attribute to it. This is the P2b 'closure writers' - reused from the same slice
    that grounds persistence, so no separate slither run is needed."""
    return sorted({fn for (_f, _l, fn) in sites.get(cell, []) if fn})


def _is_ordering_pair(a: str, b: str) -> bool:
    la, lb = a.lower(), b.lower()
    return any(r in la for r in _ORDERING_ROOTS) or any(r in lb for r in _ORDERING_ROOTS)


def _persisting_fns(ws: Path) -> set:
    """Set of NORMALIZED fn names that PERSIST state in the dataflow slice - a fn is a
    sink.fn (or path source.fn) of a state-write / storage-value / mint / burn sink, OR has a
    `via=storage` hop. A conserved-with candidate fn that neither transfers NOR appears here
    is a PURE CALCULATOR (NUVA interest.go CalculatePeriods: params in, int64 out, persists
    nothing - VMF's Go regex mis-counts local param reassignments as ledger writes). Keyed on
    genuine persistence (a state-write SINK), NOT on cell-grounding, so a Sol/Rust accounting
    fn that writes storage without transfer_hit is correctly KEPT (avoids the over-drain that
    zeroed strata/sei when keyed on grounding)."""
    fns: set = set()
    try:
        recs = _df.read_paths(str(ws), skip_degraded=True)
    except Exception:
        return fns
    persist_sink = {"state-write", "storage-value", "mint", "burn"}
    for r in recs:
        sink = r.get("sink") or {}
        if sink.get("kind") in persist_sink or any(
                h.get("via") == "storage" for h in (r.get("hops") or [])):
            for who in (sink.get("fn"), (r.get("source") or {}).get("fn")):
                if who:
                    fns.add(_norm_fn(str(who)))
    return fns


def _go_degraded_modules(ws: Path) -> list[dict]:
    """Every Go dataflow DEGRADE record, attributed to its module + reason. A degrade row is
    a genuinely STARVED module (build/load/timeout/panic/empty). read_paths skips degraded
    rows, so read raw. Returns [{module_rel, reason}]; empty => arm healthy. Attribution
    matters: a PARTIAL degrade (one module panics, the rest slice) must be NAMED, never
    silently masked by a resolved status on the healthy modules (anti-silent-suppression,
    operator-caught NUVA 2026-07-08: src/vault/simapp panicked on a golang.org/x/tools
    generics bug while the vault keeper sliced 1463 pairs - the degrade was invisible)."""
    p = ws / ".auditooor" / "dataflow_paths.jsonl"
    out: list[dict] = []
    if not p.is_file():
        return out
    import json as _json
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                r = _json.loads(line)
            except Exception:
                continue
            if r.get("language") == "go" and r.get("degraded"):
                out.append({
                    "module_rel": r.get("module_rel") or r.get("module") or "?",
                    "reason": r.get("degrade_reason") or r.get("reason") or "unknown",
                })
    except OSError:
        return out
    return out


def _go_arm_degraded(ws: Path) -> bool:
    """True when the Go dataflow ARM emitted degrade record(s) - a genuinely STARVED feeder
    (build/load/timeout/panic/empty). This is the ROBUST degraded signal, distinct from a
    HEALTHY NON-cosmos Go ws (e.g. polygon's bor/cometbft = a go-ethereum fork) whose
    state-writes legitimately carry NO collection `cell`: that ws has 0 cells but ZERO
    degrade records, and must NOT be flagged (measured 2026-07-08: the earlier
    sinks-without-cells heuristic FALSE-flagged polygon while missing nothing on the real
    degrades nuva/sei). Generic to every ws."""
    return bool(_go_degraded_modules(ws))


def _degraded_module_is_inscope(ws: Path, module_rel: str, inscope_files: list[str]) -> bool:
    """True iff a degraded MODULE directory contains any in-scope file - i.e. the starvation
    hit code we are obliged to cover. A degrade in an OOS module (test/sim/genesis wiring,
    e.g. NUVA's simapp with 0 in-scope units) does NOT block; a degrade in the CUT does. The
    scope test (not a name heuristic) is what decides whether the uncovered surface matters."""
    if not module_rel or module_rel == "?":
        return False
    mod = module_rel.rstrip("/") + "/"
    for rel in inscope_files:
        if rel == module_rel or rel.startswith(mod):
            return True
    return False


# =====================================================================================
# A13: CROSS-CONTRACT CONSERVATION (12th kind). An ACCOUNTED-TOTAL identity that SPANS
# CONTRACTS: a cell fed by an EXTERNAL-call return (e.g. `cdo.totalStrategyAssets()` /
# `strategy.totalAssets()`) that a single fn SPLITS into >=2 PERSISTENT tranche/reserve
# state cells. The whole-system invariant is  sum(split cells) == external total  (strata:
# jrtNav + srtNav + reserveNav == nav == cdo.totalStrategyAssets()). A writer that touches a
# STRICT non-empty SUBSET of the split set desyncs the tranches from the accounted total.
#
# DEDUP BOUNDARY (A1 / task note): conserved-with is INTRA-contract - it keys on VMF's
# per-fn `ledger_write_evidence` (a single-fn ledger write) and STRUCTURALLY misses this
# shape (measured on strata: VMF sees updateAccountingInner's writes as just ['reserveNav'],
# never the jrtNav/srtNav/nav split, and never the EXTERNAL-call origination). A13 reads
# SOURCE directly and is gated on an external-call hop feeding the total, so its covered_by
# signal is NOT re-derived from the conserved-with lane - the two never emit the same edge.
#
# FP-GUARD: require (a) the total to ORIGINATE from an external-call return (direct local
# `t = recv.method(...)` OR a param fed `F(recv.method(...))` at a call site) AND (b) >=2
# split targets that resolve to declared PERSISTENT contract state cells. Exclude view/pure
# fns (pure-calc: their tuple assignments are NAMED RETURNS, not SSTOREs) and snapshot/delta
# TEMPORAL variants of one root (firstNav/nav). Advisory-first, env-gated OFF (SCG_XCONTRACT),
# verdict='needs-fuzz' (NO auto-credit): the desync-is-exploitable leg needs a probe/fuzz.
_XC_NON_EXTERNAL_RECV = frozenset({
    "this", "super", "msg", "block", "tx", "abi", "address", "type", "bytes", "string",
    "uint256", "int256", "self"})
_XC_NON_ACCT_MEMBER = frozenset({
    "call", "delegatecall", "staticcall", "send", "transfer", "encode", "decode",
    "encodePacked", "encodeWithSelector", "encodeWithSignature", "sender", "value",
    "data", "timestamp", "number", "origin", "gasleft", "length", "push", "pop",
    "wrap", "unwrap", "selector"})
_XC_EXT_CALL_ASSIGN_RE = re.compile(
    r"(?<![.\w])([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(")
# the external read must be an ACCOUNTED-TOTAL (`totalAssets` / `totalStrategyAssets` /
# `nav()` / `aum()`) - NOT an arbitrary external return (a `vault.deposit()` / `x.balanceOf()`
# return is not the accounted total that splits into tranches). THE core FP-guard that keeps
# the total sourced from a genuine total-read hop (task FP note).
_XC_TOTAL_METHOD_RE = re.compile(r"total|(?<![a-z])nav|(?<![a-z])aum", re.I)
_XC_CONTROL_KW = ("if", "for", "while", "require", "return", "revert", "emit", "assert",
                  "else", "do", "try", "catch", "unchecked")
_XC_TUPLE_RE = re.compile(
    r"^\s*\(([^)]*)\)\s*(?<![=!<>+\-*/%&|^~])=(?!=)\s*(.+)$")
_XC_SINGLE_RE = re.compile(
    r"^\s*([A-Za-z_][\w.\[\]\s]*?)\s*(?<![=!<>+\-*/%&|^~])=(?!=)\s*(.+)$")
_XC_LEAD_TYPE_RE = re.compile(
    r"^(?:address|bool|string|bytes\d*|uint\d*|int\d*|mapping\s*\([^)]*\)|[A-Z]\w*)"
    r"(?:\s*\[[^\]]*\])?\s+(?:memory\s+|storage\s+|calldata\s+)?")


def _xc_lhs_cell(lhs: str) -> str | None:
    """The assigned CELL name for a Solidity LHS. Strips a leading local-decl type
    (`uint256 jrtNavT1` -> jrtNavT1) then resolves a mapping-member / struct-field / bare
    identifier via the shared _parse_lvalue (position[id].supplyShares -> supplyShares)."""
    lhs = (lhs or "").strip()
    lhs = _XC_LEAD_TYPE_RE.sub("", lhs)
    cell, _keys, _idx = _parse_lvalue(lhs)
    return cell


def _xc_iter_assignments(body: str):
    """Yield (cell_names, rhs, rhs_is_bare) per assignment statement in a comment/string-
    stripped Solidity body. Handles tuple `(uint a, uint b) = f(..)` and single `x = ..`.
    rhs_is_bare = the rhs is a lone identifier (used to spot the total-mirror `nav = navT1`)."""
    # flatten block braces so a statement is never prefixed by a `{` (which blocks the tuple
    # match on the first body statement `{ (a,b,c) = split(..) `). Assignment extraction does
    # not need block structure; conditional writes stay captured as plain assignments.
    clean = _csc._strip_strings(_csc._strip_comments(body)).replace("{", " ").replace("}", " ")
    for stmt in clean.split(";"):
        s = stmt.strip()
        if not s or any(re.match(r"^" + kw + r"\b", s) for kw in _XC_CONTROL_KW):
            continue
        mt = _XC_TUPLE_RE.match(s)
        if mt:
            inner, rhs = mt.group(1), mt.group(2).strip()
            cells = [_xc_lhs_cell(p) for p in inner.split(",")]
            cells = [c for c in cells if c]
            if cells:
                yield cells, rhs, bool(re.fullmatch(r"[A-Za-z_]\w*", rhs))
            continue
        ms = _XC_SINGLE_RE.match(s)
        if ms:
            lhs, rhs = ms.group(1), ms.group(2).strip()
            c = _xc_lhs_cell(lhs)
            if c:
                yield [c], rhs, bool(re.fullmatch(r"[A-Za-z_]\w*", rhs))


def _xc_split_cells(body: str, total: str, state_vars: set) -> tuple[list, str | None]:
    """Taint-propagate the external total `total` through `body`: return (split_cells,
    total_cell). A persistent state cell written from a bare `= total` is the total-MIRROR
    (excluded from the parts); one written from a total-DERIVED expression (through a calc /
    another split cell) is a split part. Locals in the taint chain propagate (so the
    tuple `(a,b,c)=split(..,total)` then `cellA=a` reaches the cell)."""
    tainted = {total}
    split: list = []
    total_cell = None
    seen: set = set()
    for cells, rhs, rhs_is_bare in _xc_iter_assignments(body):
        toks = set(re.findall(r"[A-Za-z_]\w*", rhs))
        if not (toks & tainted):
            continue
        rhs_is_bare_total = rhs_is_bare and rhs == total
        for c in cells:
            tainted.add(c)
            if c in state_vars:
                if rhs_is_bare_total:
                    if total_cell is None:
                        total_cell = c
                elif c not in seen:
                    seen.add(c)
                    split.append(c)
    # drop TEMPORAL variants of the total-mirror (snapshot/delta pairs, not a distinct part)
    if total_cell:
        split = [c for c in split if not _same_temporal_quantity(c, total_cell)]
    return split, total_cell


def _xc_external_total_fns(src: str, fns: list) -> dict:
    """fn_name -> (total_token, origin) for every Solidity fn whose accounted-total
    ORIGINATES from an external-call return. Two shapes:
      (a) DIRECT   : a local `t = recv.method(..)` inside the fn body (origin='direct').
      (b) PARAM-FED: the fn's FIRST param is fed `F(recv.method(..))` at a call site in src
                     (origin='param-fed'; the external hop is at the caller, cross-contract).
    recv must be a contract handle (not a builtin/self) and method an accounting read."""
    out: dict = {}
    for name, _ln, body in fns:
        # (a) direct external-call return captured into a body local
        for m in _XC_EXT_CALL_ASSIGN_RE.finditer(
                _csc._strip_strings(_csc._strip_comments(body))):
            lv, recv, meth = m.group(1), m.group(2), m.group(3)
            if (recv in _XC_NON_EXTERNAL_RECV or meth in _XC_NON_ACCT_MEMBER
                    or not _XC_TOTAL_METHOD_RE.search(meth)):
                continue
            out.setdefault(name, (lv, "direct"))
            break
    # (b) param-fed: scan call sites `name( recv.method( .. ) )` across the source
    for name, _ln, body in fns:
        if name in out:
            continue
        mp = re.search(
            re.escape(name) + r"\s*\(\s*([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(", src)
        if mp:
            recv, meth = mp.group(1), mp.group(2)
            if (recv in _XC_NON_EXTERNAL_RECV or meth in _XC_NON_ACCT_MEMBER
                    or not _XC_TOTAL_METHOD_RE.search(meth)):
                continue
            first_param = _xc_first_param(src, name)
            if first_param:
                out[name] = (first_param, "param-fed")
    return out


def _xc_first_param(src: str, fn: str) -> str | None:
    """The NAME of the first parameter of Solidity `function fn (...)` (the accounted-total
    param). `function updateAccountingInner (uint256 navT1)` -> 'navT1'."""
    m = re.search(r"\bfunction\s+" + re.escape(fn) + r"\s*\(([^)]*)\)", src)
    if not m:
        return None
    args = m.group(1).strip()
    if not args:
        return None
    first = args.split(",")[0].strip()
    toks = re.findall(r"[A-Za-z_]\w*", first)
    return toks[-1] if toks else None


def _xc_fn_state_writes(body: str, cells: set) -> set:
    """Subset of `cells` that `body` SSTOREs (assigns). Reuses the ordering detector's
    single-cell SSTORE matcher so `cell =`, `cell[..] =`, `cell +=` all count."""
    blines = _csc._strip_strings(_csc._strip_comments(body)).splitlines()
    return {c for c in cells if _sol_cell_writes(blines, c)}


def _cross_contract_conservation_edges(ws: Path, acct: dict | None = None) -> list[dict]:
    """A13 (12th kind). See the block header. Source-based, Solidity. For each fn whose
    accounted-total originates externally and splits into >=2 persistent state cells, emit
    ONE promotable cross-contract-conservation edge (kind=conserved-with, tier=cross-
    contract-conservation) whose violators are every writer touching a STRICT subset of the
    split set. Advisory-first / verdict='needs-fuzz' (NO auto-credit)."""
    if acct is not None:
        acct.setdefault("xcontract_fns_scanned", 0)
        acct.setdefault("xcontract_external_total_fns", 0)
        acct.setdefault("xcontract_split_fns", 0)
        acct.setdefault("xcontract_edges", 0)
        acct.setdefault("xcontract_examples", [])
    edges: list[dict] = []
    try:
        inscope = list(_csc._load_inscope_files(ws))
    except Exception:
        return edges
    for rel in inscope:
        if _language_of(rel) != "solidity" or _is_denied(rel):
            continue
        fp = ws / rel
        if not fp.is_file():
            continue
        src = fp.read_text(errors="replace")
        state_vars = {v for v in _sol_state_var_names(ws)}
        if not state_vars:
            continue
        fns = [(n, 0, b) for n, b in _sol_named_fns(src)]
        if acct is not None:
            acct["xcontract_fns_scanned"] += len(fns)
        # per-file fn -> persistent state cells it writes (for cross-fn subset violators)
        ext_total_fns = _xc_external_total_fns(src, fns)
        if acct is not None:
            acct["xcontract_external_total_fns"] += len(ext_total_fns)
        # header text per fn (to exclude view/pure split "writers" - named returns, not SSTORE)
        for name, _ln, body in fns:
            if name not in ext_total_fns:
                continue
            fn_header, _fb = _sol_fn_header_body(src, name)
            if re.search(r"\b(?:view|pure)\b", fn_header or ""):
                continue  # pure-calc: tuple targets are named returns, no persistent split
            total_tok, origin = ext_total_fns[name]
            split, total_cell = _xc_split_cells(body, total_tok, state_vars)
            # split cells must be genuine VALUE/amount cells (reuse the conserved-with FP
            # guards): drop rate/bps, price, bound, address/handle, snapshot/delta, nonvalue.
            split = [c for c in split if _is_value_cell(c)]
            if len(split) < 2:
                continue
            if acct is not None:
                acct["xcontract_split_fns"] += 1
            S = set(split)
            # cross-fn violators: every writer touching a STRICT non-empty subset of S.
            violators = []
            for vn, _vl, vbody in fns:
                sub = _xc_fn_state_writes(vbody, S)
                if sub and sub != S:
                    violators.append({
                        "fn": vn, "file": rel, "line": _fn_def_line(ws, rel, vn) or 0,
                        "mutates": sorted(sub), "omits": sorted(S - sub)})
            cells = sorted(S)
            a, b = cells[0], cells[1]
            sid = hashlib.sha1(
                f"xcontract:{rel}:{name}:{cells}".encode()).hexdigest()[:12]
            # promotable ONLY when every split cell is a declared persistent state var (it is,
            # by construction of _xc_split_cells) AND a total-mirror or external origin holds.
            promotable = all(c in state_vars for c in S)
            tot_desc = (f"{total_cell} (== external total)" if total_cell
                        else f"external total ({origin})")
            e = scs.new_edge(
                edge_id=sid, language="solidity", kind="conserved-with",
                cell_a=a, cell_b=b,
                writers_a=[name], writers_b=[name], violators=violators,
                confidence="semantic-ssa" if promotable else "syntactic",
                evidence={
                    "grounding": "source-external-total-split",
                    "tier": "cross-contract-conservation",
                    "subtype": "cross-contract-conservation",
                    "cross_contract": True,
                    "conserved_set": cells,
                    "external_total_token": total_tok,
                    "external_total_origin": origin,
                    "total_mirror_cell": total_cell,
                    "split_fn": name,
                    "split_site": f"{rel}:{_fn_def_line(ws, rel, name) or 0}",
                    "persistent_state": True,
                    "slice_present": (ws / ".auditooor" / "dataflow_paths.jsonl").is_file(),
                    "nviol": len(violators),
                    "promotable": promotable,
                    # advisory-first: the desync-is-exploitable leg needs a probe/fuzz.
                    "verdict": "needs-fuzz",
                    "auto_credit": False,
                    "advisory": True,
                },
                obligation=(
                    f"the sum of the split tranche/reserve cells {cells} must equal the "
                    f"accounted total {tot_desc}, which {name!r} reads from an EXTERNAL "
                    f"contract call ({origin}); a writer that mutates a strict subset of "
                    f"{cells} without the paired move desyncs the tranches from the total "
                    f"(cross-contract conservation break / insolvency)"))
            edges.append(e)
            if acct is not None and len(acct["xcontract_examples"]) < 12:
                acct["xcontract_examples"].append(
                    {"fn": name, "file": rel, "split": cells,
                     "total_cell": total_cell, "origin": origin,
                     "nviol": len(violators)})
    if acct is not None:
        acct["xcontract_edges"] = len(edges)
    return edges


def _conservation_edges(ws: Path, acct: dict | None = None) -> list[dict]:
    """P2b conserved-with: from value_moving_functions.json (a real ledger-write
    value-mover analysis) via VCIS.build_property_spec. A multi-field credit set is a
    conservation obligation; a function writing a STRICT SUBSET of that set breaks it.
    VMF-grounded => the cells are persistent ledger state by construction (bypasses the
    storage-hop persistence check, but still denylisted). This is what makes the Strata
    senior/junior conservation shape fire at the semantic tier."""
    # A13 CROSS-CONTRACT conservation (12th kind) - source-based, independent of VMF, so it
    # runs even when no value_moving_functions.json exists. Advisory-first, env-gated OFF by
    # default (SCG_XCONTRACT) so it never perturbs the existing edge byte-stream. DEDUP: A13
    # gates on an EXTERNAL-call-fed total (the conserved-with VMF lane never sees that), so it
    # never re-derives / re-emits a conserved-with edge - the two are structurally distinct.
    xcontract: list[dict] = []
    if os.environ.get("SCG_XCONTRACT") not in (None, "", "0", "no", "false"):
        xcontract = _cross_contract_conservation_edges(ws, acct=acct)
    vmf_path = ws / ".auditooor" / "value_moving_functions.json"
    if not vmf_path.is_file():
        return list(xcontract)
    try:
        import json as _json
        fns = _json.loads(vmf_path.read_text(encoding="utf-8")).get("functions", [])
    except (OSError, ValueError):
        return []
    try:
        vcis = _load_module("vcis", "value-conservation-invariant-synth.py")
    except Exception as exc:  # noqa: BLE001 - surface, do not fake a clean 0
        print(f"[state-coupling-graph] WARN: conserved-with skipped, VCIS load "
              f"failed: {exc}", file=sys.stderr)
        return []
    # PERSISTENT-CELL resolution (task_dcd6e6d3): map function-local ledger-write names
    # to the storage cells they flow into, so the cross-function subset match runs over
    # persistent identity, not per-fn locals. Identity fallback when no slice exists.
    _nc_stats: dict = {}
    name2cell = _name_to_cell(ws, stats=_nc_stats)
    _persist_fns = _persisting_fns(ws)  # fns that genuinely write storage (pure-calc drain)

    def _resolve(fn: str, name: str) -> str:
        # exact qualified key first, then the normalized bare-fn key (VMF names are bare,
        # the slice's are qualified), else identity fallback.
        return (name2cell.get((str(fn), str(name)))
                or name2cell.get((_norm_fn(str(fn)), str(name)))
                or name)

    if acct is not None:
        acct["slice_resolution_pairs"] = len(name2cell)
        # characterize a 0-pair result: broken vs inapplicable (anti-silent-suppression).
        seen = _nc_stats.get("storage_hops_seen", 0)
        distinct = _nc_stats.get("distinct_flow_hops", 0)
        acct["slice_storage_hops_seen"] = seen
        acct["slice_distinct_flow_hops"] = distinct
        acct["slice_identity_hops"] = _nc_stats.get("identity_hops", 0)
        # Go/Cosmos lane visibility (anti-silent-suppression): how many `state-write` SINK
        # cells the resolver consumed. 0 here on a Go ws means the slice was emitted by an
        # OLD go-dataflow binary without sink.cell (re-emit needed), distinct from a Sol ws
        # that legitimately has 0 Go sinks.
        acct["slice_go_sink_cells"] = _nc_stats.get("go_sink_cells", 0)
        acct["slice_go_state_write_sinks_seen"] = _nc_stats.get("go_state_write_sinks_seen", 0)
        degraded_modules = _go_degraded_modules(ws)
        go_arm_degraded = bool(degraded_modules)
        acct["slice_go_arm_degraded"] = go_arm_degraded
        # Attribute + scope-classify every degraded module. A PARTIAL degrade (some modules
        # starve, others resolve) must not be silently masked by the resolved status: record
        # WHICH modules degraded and whether ANY of them carries in-scope surface. The gate
        # (check_state_coupling) fails-closed under STRICT iff an IN-SCOPE module degraded.
        try:
            _inscope = list(_csc._load_inscope_files(ws))
        except Exception:
            _inscope = []
        acct["slice_go_degraded_modules"] = degraded_modules[:20]
        acct["slice_go_degraded_inscope"] = any(
            _degraded_module_is_inscope(ws, m.get("module_rel", ""), _inscope)
            for m in degraded_modules)
        if len(name2cell) > 0:
            # resolved on the healthy modules; if a module also degraded it is recorded above
            # (slice_go_degraded_*) and surfaced by the gate - never silently swallowed.
            acct["slice_resolution_status"] = "resolved"
        elif go_arm_degraded:
            # the Go dataflow ARM emitted a DEGRADE record (build/load/timeout/panic) -> a
            # genuinely STARVED feeder, so the Go coupled-state surface was NOT covered. A
            # LOUD degraded-feeder signal that BLOCKS done under STRICT (via check_state_
            # coupling), NOT the benign Sol `0-inapplicable`. Keyed on the degrade RECORD
            # (robust) not "sinks-without-cell" (which FALSE-flagged healthy NON-cosmos Go
            # like polygon/bor whose state-writes legitimately carry no collection cell).
            acct["slice_resolution_status"] = "0-go-feeder-degraded"
        elif seen == 0:
            acct["slice_resolution_status"] = "0-no-slice-storage-hops"
        elif distinct == 0:
            # every storage hop is identity (from==to) - a param/config `x=x` write; there
            # is NO local->distinct-cell flow to resolve. 0 is CORRECT-BY-CONSTRUCTION, not
            # a resolver failure (NUVA: 861 identity hops, whole-struct SetVaultAccount).
            acct["slice_resolution_status"] = "0-inapplicable-only-identity-hops"
        else:
            acct["slice_resolution_status"] = "0-unresolved-despite-distinct-flows"
    # field -> set of writer fns (for closure writer sets), keyed on RESOLVED identity
    # so writers_a/b collect every fn writing the same persistent cell.
    field_writers: dict[str, set[str]] = {}
    for r in fns:
        fn = r.get("function", "?")
        for f in r.get("ledger_write_evidence", []):
            field_writers.setdefault(_resolve(fn, f), set()).add(fn)
    # conserved sets = the credit-field sets of multi-field value-movers, with RATE /
    # CONFIG fields excluded (a bps/rate/ratio is a parameter, not a conserved balance
    # - keeping them floods the pair space with spurious "conservation" pairs).
    # Exclusion accounting (anti-silent-suppression): a conserved-with lane that
    # DRAINS to 0 via exclusions is indistinguishable from a genuinely-empty surface
    # unless we record WHAT was dropped and WHY. Fill `acct` so a 0 can never again be
    # an invisible tuned-zero - the emit layer surfaces a vacuity WARN when raw material
    # existed but no edge survived. Applies to every workspace + language.
    if acct is not None:
        acct.setdefault("multi_field_movers", 0)
        acct.setdefault("excluded_denied_file", 0)
        acct.setdefault("excluded_config_fn", 0)
        acct.setdefault("excluded_spec_error", 0)
        acct.setdefault("field_dropped_rate", 0)
        acct.setdefault("field_dropped_addr_snapshot", 0)
        acct.setdefault("field_dropped_nonvalue", 0)
        acct.setdefault("sets_collapsed_below_2", 0)
        acct.setdefault("surviving_conserved_sets", 0)
        acct.setdefault("surviving_examples", [])
        acct.setdefault("collapsed_examples", [])
    sets: list[tuple[frozenset, str]] = []
    _flush_cands: list[tuple] = []  # (S, file, fn) for Go fns -> intra-fn flush-group check
    _ordering_cands: list[tuple] = []  # (S, file, fn) for Sol fns -> reentrancy-ordering check
    for r in fns:
        n_writes = len(r.get("ledger_write_evidence", []))
        if acct is not None and n_writes >= 2:
            acct["multi_field_movers"] += 1
        if _is_denied(r.get("file", "")):
            if acct is not None and n_writes >= 2:
                acct["excluded_denied_file"] += 1
            continue
        if _is_config_fn(r.get("function", "")):
            if acct is not None and n_writes >= 2:
                acct["excluded_config_fn"] += 1
            continue  # config/factory/lifecycle fns re-point handles, not conserve value
        try:
            spec = vcis.build_property_spec(r)
        except Exception:
            if acct is not None and n_writes >= 2:
                acct["excluded_spec_error"] += 1
            continue
        if acct is not None:
            acct.setdefault("field_dropped_bound", 0)
            acct.setdefault("field_dropped_price", 0)
            for f in spec.credit_fields:
                if _is_rate_field(f):
                    acct["field_dropped_rate"] += 1
                elif _is_addr_or_snapshot_field(f):
                    acct["field_dropped_addr_snapshot"] += 1
                elif _is_nonvalue_field(f):
                    acct["field_dropped_nonvalue"] += 1
                elif _is_bound_field(f):
                    acct["field_dropped_bound"] += 1
                elif _is_price_field(f):
                    acct["field_dropped_price"] += 1
        # PURE-CALCULATOR drain (FP measured on NUVA interest.go CalculatePeriods 2026-07-08):
        # a fn that neither MOVES an asset (transfer_hit False) NOR PERSISTS any cell (no
        # credit field resolved to a storage cell - all raw-identity locals/params) is a pure
        # calculation, NOT a coupled-state mover. VMF's Go write-regex counts local param
        # reassignments (`vaultReserves = vaultReserves.Sub(...)`) as ledger writes, so pure
        # calculators (CalculatePeriods(vaultReserves, principal) -> int64, persists nothing)
        # leak in and seed a spurious "conserved set". Transfer-backed fns are ALWAYS kept.
        _fn = r.get("function", "?")
        if not r.get("transfer_hit") and _norm_fn(str(_fn)) not in _persist_fns:
            # neither transfers nor persists (no state-write sink for this fn in the slice)
            # -> a pure calculator, not a coupled-state mover.
            if acct is not None and n_writes >= 2:
                acct.setdefault("excluded_pure_calc", 0)
                acct["excluded_pure_calc"] += 1
            continue
        # exclude on the SEMANTIC name, then resolve the survivor to its persistent cell.
        S = frozenset(_resolve(r.get("function", "?"), f) for f in spec.credit_fields
                      if not _is_rate_field(f) and not _is_addr_or_snapshot_field(f)
                      and not _is_nonvalue_field(f) and not _is_bound_field(f)
                      and not _is_price_field(f))
        if len(S) >= 2:
            sets.append((S, r.get("file", "?")))
            _lang = _language_of(r.get("file", ""))
            if _lang == "go":
                _flush_cands.append((S, r.get("file", "?"), r.get("function", "?")))
            elif _lang == "solidity":
                _ordering_cands.append((S, r.get("file", "?"), r.get("function", "?")))
            if acct is not None:
                # LOCAL-PIPELINE reclassification (NUVA 2026-07-09, cry-wolf drain): a
                # Solidity set whose cells are ALL function-locals (none is a declared
                # contract state var, with .sol source scannable) is a linear value
                # PIPELINE (e.g. DedicatedVaultRouter._doDeposit vaultShares=vault.deposit
                # -> stakingShares=staking.deposit -> nuvaShares=nuva.deposit; each cell is
                # a call-return local feeding the next call), NOT a coupled PERSISTENT
                # invariant - it can never be partially-flushed (there is no storage to
                # desync). The promotable state-var gate already demotes these at edge
                # emission, but they still inflated surviving_conserved_sets and fired the
                # "re-probe the surviving set(s)" WARN on provably-local pipelines. Count
                # them in a distinct bucket so the WARN only cries wolf on PERSISTENT
                # survivors. `sets`/`_ordering_cands` are untouched (edge output unchanged;
                # the ordering detector already applies _sol_cell_is_local). Non-solidity
                # (Go PascalCase struct fields grounded via VMF/slice) is never reclassed.
                _persistent = [c for c in S if _internal_cell_promotable(ws, c, _lang)]
                if _lang == "solidity" and not _persistent:
                    acct.setdefault("surviving_local_pipeline_sets", 0)
                    acct["surviving_local_pipeline_sets"] += 1
                    acct.setdefault("surviving_local_pipeline_examples", [])
                    if len(acct["surviving_local_pipeline_examples"]) < 12:
                        acct["surviving_local_pipeline_examples"].append(
                            {"fn": r.get("function", "?"), "file": r.get("file", "?"),
                             "set": sorted(S)})
                else:
                    acct["surviving_conserved_sets"] += 1
                    if len(acct["surviving_examples"]) < 12:
                        acct["surviving_examples"].append(
                            {"fn": r.get("function", "?"), "file": r.get("file", "?"),
                             "set": sorted(S)})
        elif acct is not None and n_writes >= 2:
            # had >=2 raw writes but field exclusions collapsed it below the pair floor
            acct["sets_collapsed_below_2"] += 1
            # AUDITABILITY: record WHICH fns collapsed (cite-or-inadmissible) so a cited-NEGATIVE
            # over a subsystem is verifiable - e.g. NUVA's atomicallyReconcileInterest writes a
            # single whole-struct cell 'vault', collapsing to 1 -> the reader can confirm the
            # prime interest/reconcile surface was SEEN-and-drained, not silently unenumerated.
            if len(acct["collapsed_examples"]) < 20:
                acct["collapsed_examples"].append(
                    {"fn": r.get("function", "?"), "file": r.get("file", "?"),
                     "surviving_fields": sorted(S), "n_raw_writes": n_writes})
    # emit ONE edge per unordered conserved PAIR (the coupling is the pair; the
    # subset-writers are its violators) - collapses the per-(set x fn) explosion.
    pair_edges: dict[tuple, dict] = {}
    for S, sfile in sets:
        for r in fns:
            if _is_denied(r.get("file", "")) or _is_config_fn(r.get("function", "")):
                continue
            vfn = r.get("function", "?")
            wf = frozenset(_resolve(vfn, w)
                           for w in r.get("ledger_write_evidence", [])) & S
            if not wf or not (wf < S):  # need a strict, non-empty subset
                continue
            fn = r.get("function", "?")
            for w in sorted(wf):
                for o in sorted(S - wf):
                    if _same_temporal_quantity(w, o):
                        # snapshot/delta pair (same quantity at two times), not a conservation
                        if acct is not None:
                            acct["edges_dropped_temporal_snapshot"] = acct.get(
                                "edges_dropped_temporal_snapshot", 0) + 1
                        continue
                    pk = (min(w, o), max(w, o))
                    e = pair_edges.get(pk)
                    if e is None:
                        a, b = o, w
                        sid = hashlib.sha1(
                            f"conserved:{pk[0]}:{pk[1]}".encode()).hexdigest()[:12]
                        e = scs.new_edge(
                            edge_id=sid, language=_language_of(sfile),
                            kind="conserved-with", cell_a=a, cell_b=b,
                            writers_a=sorted(field_writers.get(a, set())),
                            writers_b=sorted(field_writers.get(b, set())),
                            violators=[], confidence="semantic-ssa",
                            evidence={"grounding": "vmf", "conserved_set": sorted(S),
                                      "tier": "value-conservation",
                                      "cell_resolution": ("persistent-ssa" if name2cell
                                                          else "local-name-fallback")})
                        e["evidence"]["persistent_state"] = True
                        e["evidence"]["slice_present"] = True
                        # PROMOTABLE gate: a Solidity conserved-with edge is citable ONLY when
                        # BOTH cells are contract-level STATE VARIABLES. When the dataflow slice
                        # did not ground the cells (cell_resolution=local-name-fallback), the raw
                        # VMF field name may be a function-LOCAL (snapshot/delta/temp), which has
                        # no conserved persistent invariant - the dominant conserved-with FP
                        # (measured 2026-07-08: 77/87 promotable edges were local-only). Storage-
                        # grounded (persistent-ssa) edges keep promotable; local-fallback Sol
                        # edges must pass the state-var check or demote to advisory.
                        promotable = True
                        # gate only when the originating source file is scannable (real .sol
                        # present); a VMF-only fixture (no source) cannot be judged -> do not
                        # demote (preserves prior behavior / fixtures).
                        if (_language_of(sfile) == "solidity" and not name2cell
                                and (ws / sfile).is_file()):
                            svars = _sol_state_var_names(ws)
                            if not (a in svars and b in svars):
                                promotable = False
                                e["evidence"]["demoted_reason"] = "local-only-not-state-var"
                        e["evidence"]["promotable"] = promotable
                        pair_edges[pk] = e
                    if len(e["violators"]) < 12 and not any(
                            v["fn"] == fn for v in e["violators"]):
                        vfile = r.get("file", "?")
                        e["violators"].append(
                            {"fn": fn, "file": vfile,
                             "line": _fn_def_line(ws, vfile, fn),
                             "mutates": [w], "omits": [o]})
    out = list(pair_edges.values())
    # FLUSH-GROUP (intra-fn non-atomic partial-flush, Go/Cosmos) - complements conserved-with.
    flush = _flush_group_edges(ws, _flush_cands, field_writers)
    out += flush
    ordering = _ordering_group_edges(ws, _ordering_cands, field_writers)
    out += ordering
    # A13 cross-contract conservation (env-gated OFF default; appended so the base edge
    # byte-stream is unchanged when SCG_XCONTRACT is unset).
    out += xcontract
    if acct is not None:
        acct["ordering_edges"] = len(ordering)
        acct["xcontract_conservation_edges"] = len(xcontract)
    if acct is not None:
        acct["flush_group_edges"] = len(flush)
        acct["edges_emitted"] = len(out)
        # THE telltale: raw material existed (>=1 surviving conserved set) but no edge
        # survived. On NUVA this is a LEGITIMATE 0 (deposit/redeem write their whole
        # coupled set atomically in ONE fn, so no cross-function strict-subset writer
        # exists to violate conservation), but that explanation must be VISIBLE, not
        # assumed. `no_subset_writer` distinguishes "correctly absent" from "over-pruned".
        acct["no_subset_writer"] = (len(out) == 0 and acct.get("surviving_conserved_sets", 0) > 0)
    return out


# 10th kind: CROSS-DOMAIN conservation. An INTERNAL accounting cell (share/supply) must
# move together with an EXTERNAL asset balance (bank.Send / token transfer of the
# underlying). VMF gives BOTH signals per fn: ledger_write_evidence (does it write a
# share/supply field) + transfer_hit (does it move the paired asset). The asymmetry is
# the defect: some writers of a share cell PAIR with a transfer (balanced), a sibling
# writer changes the SAME share cell WITHOUT a transfer -> shares minted/burned without
# the matching asset move = inflation / insolvency. Reuses value_moving_functions.json;
# no new slice. Advisory + PROBE-required (VMF transfer_hit is per-fn textual - a writer
# delegating the transfer to a helper is a FP the box-G probe rules out).
_SHARE_SUPPLY_RE = re.compile(
    r"share|supply|totalshares|totalsupply|mintedamount|lpamount|scaledbalance", re.I)

# a value-mover whose NAME indicates it changes share/supply via a MARKER coin / bank
# mint-burn (not a struct-field write) - e.g. cosmos BridgeMintShares / BridgeBurnShares /
# SwapIn/SwapOut minting the share marker. VMF records these as value_move with EMPTY
# ledger_write_evidence (the supply lives in an external marker/bank coin, not a field),
# so the struct-field share-writer scan is BLIND to them. They must be counted as
# UNASSESSABLE so a cited-clean can never masquerade as complete (NUVA: BridgeBurnShares
# "intentionally does not decrement vault.TotalShares" - a dual-accounting coupling the
# struct-field lane cannot see).
_SHARE_MARKER_MOVER_RE = re.compile(
    r"(?:mint|burn|swap|redeem|deposit|withdraw|bridge).*shar|shar.*(?:mint|burn|swap)"
    r"|mintshares|burnshares", re.I)


def _is_share_supply_field(f: str) -> bool:
    fl = str(f).lower()
    if _is_addr_or_snapshot_field(f) or _is_rate_field(f):
        return False
    # NOTE: do NOT apply _is_nonvalue_field here - it drops ALL Go-exported PascalCase
    # names, which wrongly excludes the real coupled value field TotalShares (the Aptos-
    # class share cell). The _SHARE_SUPPLY_RE pattern (share/supply/totalshares/...) is
    # specific enough; a store TYPE name like VaultAccount does not match it anyway.
    return bool(_SHARE_SUPPLY_RE.search(fl))


def _cross_domain_conservation_edges(ws: Path, acct: dict | None = None) -> list[dict]:
    """10th kind. A share/supply cell whose writers DISAGREE on the paired external
    value-move: >=1 writer pairs the share-write with a transfer (balanced), a sibling
    writer omits it (unbalanced) -> the unbalanced writer is a cross-domain-conservation
    violator (mint/burn shares without moving the underlying = inflation/insolvency).
    Emits nothing (cited-clean) when every share-writer is balanced OR only one writer
    exists. Semantic-ssa (VMF value-mover grounded); PROBE-required (promotable)."""
    vmf_path = ws / ".auditooor" / "value_moving_functions.json"
    if not vmf_path.is_file():
        return []
    try:
        import json as _json
        fns = _json.loads(vmf_path.read_text(encoding="utf-8")).get("functions", [])
    except (OSError, ValueError):
        return []
    # share cell -> {"balanced": [fn...], "unbalanced": [(fn,file)...]}
    cell_writers: dict[str, dict[str, list]] = {}
    n_share_writers = 0
    unassessable: list[str] = []  # share-marker movers with no share ledger field
    for r in fns:
        if _is_denied(r.get("file", "")) or _is_config_fn(r.get("function", "")):
            continue
        fn = str(r.get("function", "?"))
        shares = sorted({f for f in r.get("ledger_write_evidence", [])
                         if _is_share_supply_field(f)})
        if not shares:
            # BLIND-SPOT self-report: a value-mover named like a share-marker mint/burn
            # but with NO share ledger field changes supply via an external marker/bank
            # coin the struct-field lane cannot see - record it so the cited-clean is
            # honestly INCOMPLETE, never a false proven-clean.
            if bool(r.get("transfer_hit")) and _SHARE_MARKER_MOVER_RE.search(fn):
                unassessable.append((fn, r.get("file", "?")))
            continue
        n_share_writers += 1
        balanced = bool(r.get("transfer_hit"))
        for c in shares:
            slot = cell_writers.setdefault(c, {"balanced": [], "unbalanced": []})
            if balanced:
                slot["balanced"].append(r.get("function", "?"))
            else:
                slot["unbalanced"].append((r.get("function", "?"), r.get("file", "?")))
    # DUAL-ACCOUNTING coupling: a share struct field (TotalShares) and the share MARKER
    # coin supply must move together. A field-writer that also moves a share coin (SwapIn)
    # ESTABLISHES the coupling; a marker-only mover that changes the marker WITHOUT writing
    # the field (BridgeBurnShares) is a violator (TotalShares <-> marker-supply divergence).
    # This ASSESSES the previously-"unassessable" marker movers against a concrete cell
    # pair, firing a real semantic-ssa lead (probe-gated) instead of a blind incomplete.
    field_cells = sorted(cell_writers)  # share struct fields with writers (e.g. TotalShares)
    if acct is not None:
        acct["cross_domain_share_writers"] = n_share_writers
        acct["cross_domain_cells"] = len(cell_writers)
        acct["cross_domain_unassessable_share_movers"] = sorted({f for f, _ in unassessable})
        # ASSESSED once a field-writer exists to couple against; else genuinely unassessable.
        acct["cross_domain_assessment_complete"] = (len(unassessable) == 0
                                                    or bool(field_cells))
    edges: list[dict] = []
    n_asym = 0
    for cell, slot in sorted(cell_writers.items()):
        # asymmetry needed: at least one balanced (establishes the pairing obligation)
        # AND at least one unbalanced (the violator). All-balanced or all-unbalanced is
        # NOT a conservation break at this granularity (cited-clean).
        if not slot["balanced"] or not slot["unbalanced"]:
            continue
        n_asym += 1
        vio = [{"fn": fn, "file": fl, "line": _fn_def_line(ws, fl, fn),
                "mutates": [cell], "omits": ["external:underlying-asset-balance"]}
               for fn, fl in slot["unbalanced"][:12]]
        lang = _language_of(slot["unbalanced"][0][1])
        sid = hashlib.sha1(f"xdomain:{cell}".encode()).hexdigest()[:12]
        e = scs.new_edge(
            edge_id=sid, language=lang, kind="cross-domain-conservation",
            cell_a=cell, cell_b="external:underlying-asset-balance",
            writers_a=sorted(set(slot["balanced"] + [f for f, _ in slot["unbalanced"]])),
            writers_b=sorted(slot["balanced"]),
            violators=vio, confidence="semantic-ssa",
            evidence={"grounding": "vmf-transfer-asymmetry",
                      "balanced_writers": sorted(slot["balanced"]),
                      "unbalanced_writers": sorted(f for f, _ in slot["unbalanced"]),
                      "tier": "cross-domain-conservation"},
            obligation=(f"every writer of the internal share/supply cell {cell!r} must "
                        "move the paired external underlying-asset balance by the "
                        "corresponding amount; a writer that omits the transfer inflates "
                        "or deflates shares vs assets (insolvency)"))
        e["evidence"]["persistent_state"] = True
        e["evidence"]["slice_present"] = True
        _prom = _internal_cell_promotable(ws, cell, lang)
        e["evidence"]["promotable"] = _prom
        if not _prom:
            e["evidence"]["demoted_reason"] = "internal-cell-not-state-var"
        edges.append(e)
    # DUAL-ACCOUNTING edge: marker-only movers vs a share struct field (both must move).
    n_dual = 0
    if unassessable and field_cells:
        cell = field_cells[0]  # the internal accounting field (e.g. TotalShares)
        vio = [{"fn": fn, "file": fl, "line": _fn_def_line(ws, fl, fn),
                "mutates": ["external:share-marker-supply"], "omits": [cell]}
               for fn, fl in unassessable[:12]]
        lang = _language_of(unassessable[0][1])
        sid = hashlib.sha1(f"dualacct:{cell}".encode()).hexdigest()[:12]
        fieldw = sorted({w for slot in cell_writers.values()
                         for w in slot["balanced"] + [f for f, _ in slot["unbalanced"]]})
        e = scs.new_edge(
            edge_id=sid, language=lang, kind="cross-domain-conservation",
            cell_a=cell, cell_b="external:share-marker-supply",
            writers_a=fieldw, writers_b=sorted({f for f, _ in unassessable}),
            violators=vio, confidence="semantic-ssa",
            evidence={"grounding": "vmf-dual-accounting-asymmetry",
                      "field_writers": fieldw,
                      "marker_only_movers": sorted({f for f, _ in unassessable}),
                      "tier": "cross-domain-conservation-dual-accounting"},
            obligation=(f"the internal accounting field {cell!r} and the external share-"
                        "marker coin supply must move together; a fn that mints/burns the "
                        "share marker WITHOUT writing {cell} (or vice versa) desyncs the two "
                        "share ledgers (share-inflation / over-redemption / insolvency)"))
        e["evidence"]["persistent_state"] = True
        e["evidence"]["slice_present"] = True
        _prom = _internal_cell_promotable(ws, cell, lang)
        e["evidence"]["promotable"] = _prom
        if not _prom:
            e["evidence"]["demoted_reason"] = "internal-cell-not-state-var"
        edges.append(e)
        n_dual = 1
    if acct is not None:
        acct["cross_domain_asymmetric_cells"] = n_asym
        acct["cross_domain_dual_accounting_edges"] = n_dual
        acct["cross_domain_edges"] = len(edges)
    return edges


# P8: freshness tokens - WORD-BOUNDED (bare substrings flood: "ttl" matched
# "seTTLement"). Dotted forms kept literal. A cell referenced in a function carrying
# one of these is freshness-guarded.
_FRESH_RE = re.compile(
    r"\b(?:updatedat|answeredinround|roundid|maxstale|staleness|stalethreshold|"
    r"staleperiod|lastupdate|heartbeat|deadline|freshness|graceperiod|ttl|expiry|"
    r"expiration|lastrefresh|priceage|updatedround)\b|block\.(?:timestamp|number)",
    re.I)


def _freshness_edges(src: str, rel: str) -> list[dict]:
    """P8 - the 9th kind. A state value is coupled to an EXTERNAL clock the contract
    never writes (block.timestamp / oracle round / TTL). The writer-mutates-B-not-A
    model cannot express it (no on-chain writer on the time endpoint), so the defect
    is detected as ASYMMETRIC freshness enforcement: cell A is used under a freshness
    gate in >=1 reader, but a SIBLING consumer reads A WITHOUT that gate. That consumer
    is the citable violator (stale value drives a decision)."""
    if _is_denied(rel):
        return []
    fns = [(n, ln, _csc._strip_strings(_csc._strip_comments(b)))
           for n, ln, b in _csc._functions(src)]
    if not fns:
        return []
    file_state: set[str] = set()
    for _n, _l, b in fns:
        file_state |= _csc._state_cells(b)
    file_state = {c for c in file_state if len(c) >= 3}
    if not file_state:
        return []
    guarded: dict[str, set[str]] = {}
    consumers: dict[str, list] = {}
    for name, line, b in fns:
        fresh_spans = [mo.start() for mo in _FRESH_RE.finditer(b)]
        writes = _csc._state_cells(b)
        words = set(_csc._WORD_RE.findall(b))
        for a in file_state & words:
            # A is GUARDED here only if it appears NEAR a freshness token (the gate
            # is freshness(A), not just any timestamp in the function - the proximity
            # ties the staleness check to THIS cell and cuts co-occurrence FPs).
            occ = [mm.start() for mm in re.finditer(r"\b" + re.escape(a) + r"\b", b)]
            near = any(abs(o - fs) < 80 for o in occ for fs in fresh_spans)
            if near:
                guarded.setdefault(a, set()).add(name)
            elif not fresh_spans and a not in writes:
                # a fn with NO freshness token that READS A (not its writer) = a
                # consumer that skips the staleness check a guarded reader applies.
                consumers.setdefault(a, []).append((name, line))
    edges = []
    for a, gset in guarded.items():
        cons = [(n, ln) for (n, ln) in consumers.get(a, []) if n not in gset]
        if not cons:
            continue
        sid = hashlib.sha1(f"{rel}:freshness:{a}".encode()).hexdigest()[:12]
        e = scs.new_edge(
            edge_id=sid, language=_language_of(rel),
            kind="freshness-coupled-to-external-clock",
            cell_a=a, cell_b="external-clock",
            writers_a=sorted(gset), writers_b=[],
            violators=[{"fn": n, "file": rel, "line": ln,
                        "mutates": ["external-clock"], "omits": [a]}
                       for n, ln in cons[:12]],
            confidence="syntactic",
            evidence={"tier": "freshness-asymmetry",
                      "guarded_readers": sorted(gset)})
        e["evidence"]["persistent_state"] = True
        e["evidence"]["slice_present"] = True
        # ADVISORY PROMPT: the asymmetry is regex-detected (a "consumer" may enforce
        # freshness via a modifier / internal call the regex misses), so it is NOT
        # auto-promotable - it surfaces as a probe obligation and only reaches the
        # exploit-queue after a probe confirms (see _gather_from_state_coupling).
        e["evidence"]["promotable"] = False
        edges.append(e)
    return edges


# A12: FRESHNESS-COUPLED-TO-SHARED-CURSOR (a freshness SIBLING kind, cross-module). See the
# schema block for the taxonomy note. Cell A is a SNAPSHOT of an ON-CHAIN cursor the protocol
# ADVANCES, read cross-module via `X.epoch()` / `X.checkpoint()` (method root in _ORDERING_
# ROOTS), where that cursor has a PROVEN NON-MONOTONIC writer (a set/reset fn assigning it from
# an arbitrary value, or a `delete` - so it can roll BACK / reorg, not just increase) AND a
# SIBLING reader trusts the stored A without re-establishing it. On a rollback the stored A
# desyncs from the live cursor (Polygon ValidatorShare withdrawEpoch = stakeManager.epoch() vs
# _unstakeClaimTokens' withdrawEpoch+delay<=epoch settle gate). Trigger = rollover/reset/reorg,
# NOT age.
#
# DEDUP / FP-GUARD (A1 boundary): the external-CLOCK lane (_freshness_edges) keys cell_b=
# 'external-clock' on block.timestamp / oracle-round TOKENS the contract never writes; A12 keys
# cell_b='shared-cursor:<root>' and fires ONLY on a cross-module method read + a PROVEN
# non-monotonic writer, so the two never emit the same edge (emitted hits are further deduped by
# (file, cell_a) vs the external-clock edges). Excludes intra-fn SLOAD-to-local gas caching
# (`uint256 _e = currentEpoch;` is a BARE state-var read with no `.method()` call -> never
# matches _CURSOR_READ_RE). Distinct from interruption (atomicity / push-pop record split).
# Advisory-first, env-gated OFF (SCG_SHARED_CURSOR), verdict='needs-fuzz' (NO auto-credit): the
# desync-is-exploitable leg needs a reorg/reset reachability probe.
_CURSOR_READ_RE = re.compile(
    r"([A-Za-z_][\w.\[\]]*?)\s*(?<![=!<>+\-*/%&|^~])=(?!=)\s*"
    r"([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\([^;{}]*\)")
# struct-literal field init `withdrawEpoch: X.epoch()`
_CURSOR_FIELD_RE = re.compile(
    r"([A-Za-z_]\w*)\s*:\s*([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\([^;{},]*\)")
# a fn whose NAME marks it a non-monotonic mutator of a cursor (reset/override/rollback/setter).
_NONMONO_FN_RE = re.compile(
    r"^(?:set|reset|force|override|rollback|revert|adjust|init|restore|rewind)", re.I)
# a plain SSTORE `cell = rhs;` (not compound / comparison; the cell char-class holds no `.`/`[`
# so a local-decl `uint256 _e = ..` LHS `_e` matches but is filtered by the state-var check).
_CURSOR_ASSIGN_RE = re.compile(
    r"(?:^|[;{}]|\)\s*)\s*([A-Za-z_]\w*)\s*(?<![=!<>+\-*/%&|^~])=(?!=)\s*([^;]+);")
_CURSOR_DELETE_RE = re.compile(r"\bdelete\s+([A-Za-z_]\w*)\b")


def _cursor_root(method: str) -> str | None:
    """The _ORDERING_ROOTS token a cursor method/var name carries (epoch/checkpoint/round/...),
    else None. Used to tie a cross-module `X.epoch()` read to a non-monotonic writer of the
    SAME cursor root."""
    ml = str(method).lower()
    for r in _ORDERING_ROOTS:
        if r in ml:
            return r
    return None


def _cursor_nonmonotonic_writers(ws: Path) -> dict[str, dict]:
    """root -> {file, fn, line, cell, how} for the FIRST PROVEN non-monotonic writer of a
    cursor-rooted STATE VARIABLE in the ws. Non-monotonic = EITHER (a) a set/reset/override-
    named fn that assigns the cursor var with a plain `=` that is NOT a self-increment
    (`cell = cell + n` / `cell.add(..)`), OR (b) a `delete <cursorVar>`. This is the PROVEN-
    writer gate (spec FP-guard): a cursor that only ever monotonically increases cannot roll
    back, so no snapshot desync. Cross-module by construction (the writer lives in the cursor's
    OWNER module; the reader snapshots it elsewhere)."""
    svars = _sol_state_var_names(ws)
    cursor_vars = {v for v in svars if _cursor_root(v)}
    out: dict[str, dict] = {}
    if not cursor_vars:
        return out
    try:
        sol_files = [f for f in ws.rglob("*.sol")
                     if not _is_denied(str(f.relative_to(ws)) if str(f).startswith(str(ws)) else str(f))]
    except OSError:
        return out
    for f in sol_files:
        try:
            src = f.read_text(errors="replace")
        except OSError:
            continue
        rel = str(f.relative_to(ws)) if str(f).startswith(str(ws)) else str(f)
        for name, body in _sol_named_fns(src):
            b = _csc._strip_strings(_csc._strip_comments(body))
            setter = bool(_NONMONO_FN_RE.match(name))
            # (b) delete of a cursor var -> non-monotonic regardless of fn name.
            for dm in _CURSOR_DELETE_RE.finditer(b):
                cv = dm.group(1)
                r = cv in cursor_vars and _cursor_root(cv)
                if r and r not in out:
                    out[r] = {"file": rel, "fn": name,
                              "line": _fn_def_line(ws, rel, name), "cell": cv, "how": "delete"}
            if not setter:
                continue
            # (a) a set/reset-named fn assigning the cursor var from a non-self-increment rhs.
            for am in _CURSOR_ASSIGN_RE.finditer(b):
                cv, rhs = am.group(1), am.group(2)
                r = cv in cursor_vars and _cursor_root(cv)
                if not r:
                    continue
                monotonic = re.search(re.escape(cv) + r"\s*(?:\.\s*add\s*\(|\+)", rhs) is not None
                if not monotonic and r not in out:
                    out[r] = {"file": rel, "fn": name,
                              "line": _fn_def_line(ws, rel, name), "cell": cv, "how": "setter"}
    return out


def _freshness_shared_cursor_edges(ws: Path, fresh_edges: list[dict] | None = None) -> list[dict]:
    """See the A12 header above. One advisory `freshness-coupled-to-shared-cursor` edge per
    (file, cell A) where (1) a fn assigns cell A from a CROSS-MODULE cursor read `X.epoch()`
    (root in _ORDERING_ROOTS, X a cross-module handle - NOT block/msg/tx/abi), (2) that cursor
    root has a PROVEN non-monotonic writer in the ws, and (3) a SIBLING reader references A but
    is NOT a source-writer (it trusts the stored snapshot). verdict='needs-fuzz' (NO auto-
    credit). DEDUP: (file, cell A) already emitted by the external-clock lane is skipped."""
    edges: list[dict] = []
    nonmono = _cursor_nonmonotonic_writers(ws)
    if not nonmono:
        return edges  # PROVEN-writer gate: no reset/reorg surface -> not this class
    # DEDUP set vs the external-CLOCK freshness lane (A1: dedup emitted hits, do NOT re-derive).
    clock_cover: set[tuple] = set()
    for fe in (fresh_edges or []):
        if fe.get("kind") == "freshness-coupled-to-external-clock":
            for v in fe.get("violators", []):
                clock_cover.add((v.get("file"), fe.get("cell_a")))
    for rel in _csc._load_inscope_files(ws):
        if _language_of(rel) != "solidity" or _is_denied(rel):
            continue
        fp = ws / rel
        if not fp.is_file():
            continue
        src = fp.read_text(errors="replace")
        # _sol_named_fns (function-keyword parser) is robust to multi-line signatures and never
        # mistakes a mapping/struct declaration for a fn body (the _csc._functions per-line
        # mis-parse that swallowed a body into a `mapping` decl). Lines resolved via _fn_def_line.
        fns = [(n, _fn_def_line(ws, rel, n), _csc._strip_strings(_csc._strip_comments(b)))
               for n, b in _sol_named_fns(src)]
        if not fns:
            continue
        # (cell A) -> {root, recv, source_writers[]} from cross-module cursor reads.
        srcinfo: dict[str, dict] = {}
        for name, _ln, b in fns:
            for mm in list(_CURSOR_READ_RE.finditer(b)) + list(_CURSOR_FIELD_RE.finditer(b)):
                lhs, recv, method = mm.group(1), mm.group(2), mm.group(3)
                if recv in _XC_NON_EXTERNAL_RECV:
                    continue  # not a cross-module handle (block/msg/tx/abi/this/... -> clock lane)
                root = _cursor_root(method)
                if not root or root not in nonmono:
                    continue
                cell = _xc_lhs_cell(lhs) if "." in lhs or "[" in lhs else lhs.strip()
                if not cell or len(cell) < 4 or cell == recv:
                    continue
                info = srcinfo.setdefault(cell, {"root": root, "recv": recv, "writers": set()})
                info["writers"].add(name)
        if not srcinfo:
            continue
        for cell, info in sorted(srcinfo.items()):
            if (rel, cell) in clock_cover:
                continue  # covered by the external-clock lane already
            wrx = re.compile(r"\b" + re.escape(cell) + r"\b")
            readers = [(n, ln) for (n, ln, b) in fns
                       if n not in info["writers"] and wrx.search(b)]
            if not readers:
                continue
            nm = nonmono[info["root"]]
            sid = hashlib.sha1(f"{rel}:shared-cursor:{cell}".encode()).hexdigest()[:12]
            e = scs.new_edge(
                edge_id=sid, language="solidity",
                kind="freshness-coupled-to-shared-cursor",
                cell_a=cell, cell_b="shared-cursor:" + info["root"],
                writers_a=sorted(info["writers"]), writers_b=[nm["fn"]],
                violators=[{"fn": n, "file": rel, "line": ln,
                            "mutates": ["shared-cursor:" + info["root"]], "omits": [cell]}
                           for n, ln in readers[:12]],
                confidence="syntactic",
                evidence={"tier": "freshness-shared-cursor", "verdict": "needs-fuzz",
                          "advisory": True, "auto_credit": False, "promotable": False,
                          "persistent_state": True, "slice_present": True,
                          "cursor_root": info["root"], "cursor_recv": info["recv"],
                          "source_writers": sorted(info["writers"]),
                          "sibling_readers": sorted({n for n, _ in readers}),
                          "nonmonotonic_writer": {"fn": nm["fn"], "file": nm["file"],
                                                  "line": nm["line"], "how": nm["how"],
                                                  "cursor_cell": nm["cell"]},
                          "note": "cell A snapshots a cross-module cursor with a PROVEN non-"
                                  "monotonic writer; a sibling reader trusts the stored value. "
                                  "A rollover/reset/reorg desyncs it - reachability of the "
                                  "reset is the fuzz obligation (NOT auto-credited)"})
            edges.append(e)
    return edges


# =====================================================================================
# R1 HANDLE-FRESHNESS ARM - 14th SCG kind "stale-handle-after-recycle". See the schema block +
# reports/state_coupling_completeness_framework_design.md. The READ/HOLD side of a reusable
# identity handle: a handle correctly unique at ISSUANCE has its slot FREED (pop / swap-pop
# C[i]=C[len-1] / delete C[k] / _burn / EnumerableSet.remove / Table::remove / move_from) and
# RE-ISSUED to a NEW occupant, and a STALE HOLDER persisted across a tx/step/epoch resolves the
# recycled slot BLINDLY (no binding-freshness re-check) into a severity-eligible sink. The namesake
# Hexens 'Arbitrary Struct Hijack in Aptos Move VM' 0-day. DISJOINT from A4 (write-collision on
# ISSUANCE: no recycle, no persisted holder) and A12 (numeric-cursor MONOTONICITY: a number rolling
# back, not a freed+reissued slot's referent IDENTITY). Advisory-first, env-gated OFF
# (SCG_HANDLE_FRESHNESS); verdict='needs-fuzz' (recycle reachability is the fuzz obligation). The
# TRIPLE (holder H, handle-space container C, recycle event R) drives a binding-freshness soundness
# check inside the resolving fn B: ANY re-validation witness (generation-counter compare / referent
# -identity assert / existence+owner re-read / monotonic-not-recycled proof) => GREEN, no edge.

# set (2) RECYCLE EVENTS - what FREES a handle-space slot in a Solidity container C.
_HF_POP_RE = re.compile(r"(?<![.\w])([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*\.\s*pop\s*\(")
_HF_DELETE_RE = re.compile(r"\bdelete\s+([A-Za-z_]\w*)\s*\[")
_HF_SETREMOVE_RE = re.compile(r"(?<![.\w])([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*\.\s*remove\s*\(")
# swap-pop reindex `C[i] = C[C.length-1];` MOVES the last element's identity onto slot i (the exact
# stale-holder trigger - a stored index to the old last element now resolves to a different one).
_HF_SWAPPOP_RE = re.compile(r"(?<![.\w])([A-Za-z_]\w*)\s*\[[^\]]+\]\s*=\s*([A-Za-z_]\w*)\s*\[")
# Move recycle (frees the referent a cached type-tag/StructNameIndex points at) + type-tag handle.
_HF_MOVE_RECYCLE_RE = re.compile(r"\bmove_from\s*<|\bTable::remove\b|\bSmartTable::remove\b|\bdestroy\b")
_HF_MOVE_TAG_RE = re.compile(r"\btype_of\s*<|\btype_name\s*<|\bStructNameIndex\b")

# severity-eligible SINK families (the blind-resolve target that makes an edge gate-worthy).
_HF_VALUE_SINK_RE = re.compile(
    r"\.\s*transfer\s*\(|\.\s*send\s*\(|\bsafeTransfer(?:From)?\s*\(|\btransferFrom\s*\("
    r"|(?<![.\w])_?mint\s*\(|(?<![.\w])_?burn\s*\(|\.\s*call\s*\{[^}]*value")
_HF_TYPECAST_SINK_RE = re.compile(r"\babi\s*\.\s*decode\s*\(")
_HF_MOVE_SINK_RE = re.compile(r"\bmove_to\b|\bborrow_global_mut\s*<|\bdispatch\b")

# re-validation WITNESSES (any present in the resolving body => GREEN precision guard, no edge).
_HF_GEN_WITNESS_RE = re.compile(
    r"\.\s*(?:gen|generation|version|epoch|nonce|seq|firstLive)\b[^;{}]{0,64}(?:==|!=|>=|<=|<|>)"
    r"|(?:==|!=|>=|<=|<|>)[^;{}]{0,64}\.\s*(?:gen|generation|version|epoch|nonce|seq|firstLive)\b",
    re.I)
_HF_OWNER_WITNESS_RE = re.compile(
    r"\.\s*(?:owner|beneficiary|holder|account|addr)\b[^;{}]{0,64}(?:==|!=)"
    r"|(?:==|!=)[^;{}]{0,64}\.\s*(?:owner|beneficiary|holder|account|addr)\b", re.I)

# UN-ANALYZED (unsupported-language) shapes - a recycle op + a persisted-handle field in a language
# the arm has NO parser for (Go/Rust/...); an un-enumerated holder of a recyclable handle must block
# under the dedicated enforce env, never masquerade as a clean 0 (anti-silent-suppression).
_HF_UNSUP_RECYCLE_RE = re.compile(
    r"\bswap_remove\s*\(|\.\s*pop\s*\(|(?<![.\w])delete\s*\(|\.\s*remove\s*\(|\bmove_from\s*<"
    r"|\bTable::remove\b")
_HF_UNSUP_HOLDER_RE = re.compile(
    r"\b\w*(?:Id|Idx|Index|Slot|Handle|Tag)\b\s*=(?!=)"
    r"|\b\w+_(?:id|idx|index|slot|handle|tag)\b\s*=(?!=)")


def _hf_witness_present(body: str) -> bool:
    """A binding-freshness re-check on the resolved referent (any witness => GREEN)."""
    return bool(_HF_GEN_WITNESS_RE.search(body) or _HF_OWNER_WITNESS_RE.search(body))


def _hf_sink_class(body: str) -> str | None:
    if _HF_VALUE_SINK_RE.search(body):
        return "value-move"
    if _HF_TYPECAST_SINK_RE.search(body):
        return "type-cast"
    if _HF_MOVE_SINK_RE.search(body):
        return "authority"
    return None


def _hf_write_fns(fnc: list[tuple[str, str]], holder: str) -> set[str]:
    """Fns that WRITE state var `holder` (`H = ..` / `H[..] = ..`) - the issuance/store sites."""
    pat = re.compile(r"(?<![.\w])" + re.escape(holder) +
                     r"\s*(?:\[[^\]]*\])*\s*(?<![=!<>+\-*/%&|^~])=(?!=)")
    return {n for n, b in fnc if pat.search(b)}


def _hf_solidity_edges(ws: Path, rel: str, src: str, svars: set, storage_cells: set) -> list[dict]:
    """Per Solidity file: build the recyclable-container set (2), the holder set (3), and drive the
    binding-freshness check per (holder H, container C). One edge per (H, C) with >=1 blind resolve
    (C[H] -> severity-eligible sink, NO witness) where C has >=1 recycle event."""
    edges: list[dict] = []
    fnc = [(n, _csc._strip_strings(_csc._strip_comments(b))) for n, b in _sol_named_fns(src)]
    if not fnc:
        return edges
    # (2) recyclable containers C (declared state vars, NOT an _ORDERING_ROOTS numeric cursor = A12).
    recycle: dict[str, list[tuple[str, str]]] = {}

    def _add(c: str, fn: str, op: str) -> None:
        if c in svars and not _cursor_root(c):
            recycle.setdefault(c, []).append((fn, op))

    for n, b in fnc:
        for m in _HF_POP_RE.finditer(b):
            _add(m.group(1), n, "pop")
        for m in _HF_DELETE_RE.finditer(b):
            _add(m.group(1), n, "delete")
        for m in _HF_SETREMOVE_RE.finditer(b):
            _add(m.group(1), n, "remove")
        for m in _HF_SWAPPOP_RE.finditer(b):
            if m.group(1) == m.group(2):
                _add(m.group(1), n, "swap-pop")
    if not recycle:
        return edges  # no recycle event -> every handle is monotonic-never-recycled -> GREEN
    # holder-writer sets: a HOLDER H = a declared state var written in >=1 fn (persist-across-boundary
    # is gated by state-var membership; an intra-fn local index is NOT a holder = issuance-side A4).
    hwrite: dict[str, set[str]] = {}
    for H in svars:
        if _cursor_root(H):
            continue  # a numeric cursor holder is A12's turf, not identity-freshness
        w = _hf_write_fns(fnc, H)
        if w:
            hwrite[H] = w
    for C in sorted(recycle):
        cread = re.compile(r"(?<![.\w])" + re.escape(C) + r"\s*\[([^\]]+)\]")
        blind: dict[str, set[str]] = {}
        for n, b in fnc:
            idxs = [mm.group(1) for mm in cread.finditer(b)]
            if not idxs:
                continue
            # indirect resolve: `uint idx = slotOf[msg.sender]; ... C[idx]` - map a local to its holder.
            local_from_holder: dict[str, str] = {}
            for am in re.finditer(r"(?<![.\w])([A-Za-z_]\w*)\s*(?<![=!<>+\-*/%&|^~])=(?!=)\s*([^;]+);", b):
                lhs, rhs = am.group(1), am.group(2)
                rtoks = set(_csc._WORD_RE.findall(rhs))
                for H in hwrite:
                    if H in rtoks:
                        local_from_holder.setdefault(lhs, H)
            resolved: set[str] = set()
            for idx in idxs:
                for t in set(_csc._WORD_RE.findall(idx)):
                    if t in hwrite:
                        resolved.add(t)
                    elif t in local_from_holder:
                        resolved.add(local_from_holder[t])
            if not resolved:
                continue
            if not _hf_sink_class(b):
                continue  # resolved referent does NOT flow into a severity-eligible sink -> benign
            if _hf_witness_present(b):
                continue  # GREEN: a binding-freshness re-check is present in the resolving body
            for H in resolved:
                if n in hwrite.get(H, set()):
                    continue  # B re-issues/re-reads H from a fresh lookup -> not a stale holder
                blind.setdefault(H, set()).add(n)
        for H in sorted(blind):
            readers = sorted(blind[H])
            recycle_fns = sorted({fn for fn, _ in recycle[C]})
            recycle_ops = sorted({op for _, op in recycle[C]})
            sink = None
            for n, b in fnc:
                if n in readers:
                    sink = _hf_sink_class(b)
                    break
            persisted = (H in storage_cells) if storage_cells else (H in svars)
            # promotable ONLY on the strong 3-leg witness: proven recycle-event writer + persisted-
            # across-boundary holder + blind resolve into a value-move / type-cast sink. Demoted to
            # advisory unless the dedicated enforce env (state-coupling-completeness-check).
            promotable = bool(persisted and C in svars and sink in ("value-move", "type-cast"))
            sid = hashlib.sha1(f"{rel}:stale-handle:{H}:{C}".encode()).hexdigest()[:12]
            edges.append(scs.new_edge(
                edge_id=sid, language="solidity", kind="stale-handle-after-recycle",
                cell_a="holder:" + H, cell_b="handle-space:" + C,
                writers_a=sorted(hwrite.get(H, set()) | set(recycle_fns)),
                writers_b=recycle_fns,
                violators=[{"fn": rf, "file": rel, "line": _fn_def_line(ws, rel, rf),
                            "mutates": ["handle-space:" + C], "omits": ["freshness:" + H]}
                           for rf in readers],
                confidence="syntactic",
                evidence={"tier": "handle-freshness", "verdict": "needs-fuzz",
                          "advisory": True, "auto_credit": False, "promotable": promotable,
                          "persistent_state": True, "slice_present": bool(storage_cells),
                          "issuance_sites": sorted(hwrite.get(H, set())),
                          "recycle_events": recycle_fns, "recycle_op": recycle_ops,
                          "sink_class": sink, "revalidation_absent": True,
                          "note": "stale holder resolves a recycled slot to a NEW occupant without a "
                                  "binding-freshness re-check (Aptos struct-hijack shape); recycle "
                                  "reachability is the fuzz obligation"}))
    return edges


def _hf_move_edges(ws: Path, rel: str, src: str) -> list[dict]:
    """Move specialization (subsumes backlog M3, THE namesake exploit): a cached type-tag /
    StructNameIndex handle + a move_from/Table::remove/destroy recycle of the referent + no identity
    re-validation witness -> type-dispatch resolves a stale tag. One advisory edge per file."""
    body = _csc._strip_strings(_csc._strip_comments(src))
    if not (_HF_MOVE_RECYCLE_RE.search(body) and _HF_MOVE_TAG_RE.search(body)):
        return []
    if _hf_witness_present(body):
        return []  # GREEN: an identity assert re-establishes the tag before dispatch
    recycle_ops = sorted({op for op, rx in (
        ("move_from", r"\bmove_from\s*<"), ("Table::remove", r"\bTable::remove\b"),
        ("destroy", r"\bdestroy\b")) if re.search(rx, body)})
    sink = _hf_sink_class(body) or "type-cast"
    sid = hashlib.sha1(f"{rel}:stale-handle-move".encode()).hexdigest()[:12]
    return [scs.new_edge(
        edge_id=sid, language="move", kind="stale-handle-after-recycle",
        cell_a="holder:type-tag", cell_b="handle-space:type-table",
        writers_a=[], writers_b=[],
        violators=[{"fn": "<type-dispatch>", "file": rel, "line": 0,
                    "mutates": ["handle-space:type-table"], "omits": ["freshness:type-tag"]}],
        confidence="syntactic",
        evidence={"tier": "handle-freshness", "verdict": "needs-fuzz", "advisory": True,
                  "auto_credit": False, "promotable": False, "persistent_state": True,
                  "slice_present": False, "language_specialization": "move",
                  "issuance_sites": ["type_of/type_name/StructNameIndex"],
                  "recycle_events": recycle_ops, "recycle_op": recycle_ops, "sink_class": sink,
                  "revalidation_absent": True,
                  "note": "cached type_of/StructNameIndex reused after move_from/Table::remove/"
                          "destroy freed the referent; type-dispatch on the stale tag resolves a "
                          "NEW occupant (Hexens Aptos Move-VM struct-hijack) - recycle reachability "
                          "is the fuzz obligation"})]


def _handle_freshness_edges(ws: Path, prior_edges: list[dict] | None = None) -> list[dict]:
    """R1 handle-freshness arm (see the header). Enumerates the (holder, recyclable-handle, recycle-
    event) TRIPLE per in-scope file and drives the binding-freshness soundness check; one advisory
    `stale-handle-after-recycle` edge per blindly-resolved (holder, container). Persists an accounting
    sidecar (.auditooor/state_coupling_handle_freshness.json) with the un-analyzed-inscope flag so a
    STARVED arm (recyclable handle in an unsupported language) cannot masquerade as a clean 0. DEDUP
    vs A12 (prior_edges) by (file, cell_a); numeric-cursor holders/containers are skipped (A12 turf).
    DISJOINT from A4 by construction (requires a recycle event + a persisted holder)."""
    edges: list[dict] = []
    svars = _sol_state_var_names(ws)
    try:
        storage_cells, _sites = _storage_facts(ws)
    except Exception:  # noqa: BLE001
        storage_cells = set()
    # A12 dedup cover: (file, cell_a) already emitted by the shared-cursor lane (do NOT re-derive).
    a12_cover: set[tuple] = set()
    for pe in (prior_edges or []):
        if pe.get("kind") == "freshness-coupled-to-shared-cursor":
            for v in pe.get("violators", []):
                a12_cover.add((v.get("file"), pe.get("cell_a")))
    unanalyzed_examples: list = []
    analyzed_langs: set[str] = set()
    recyclable_containers = 0
    for rel in _csc._load_inscope_files(ws):
        if _is_denied(rel):
            continue
        fp = ws / rel
        if not fp.is_file():
            continue
        lang = _language_of(rel)
        src = fp.read_text(errors="replace")
        if lang == "solidity":
            analyzed_langs.add("solidity")
            fedges = _hf_solidity_edges(ws, rel, src, svars, storage_cells)
            recyclable_containers += len({e["cell_b"] for e in fedges})
            for e in fedges:
                if (rel, e["cell_a"]) in a12_cover:
                    continue  # deduped vs the A12 shared-cursor lane
                edges.append(e)
        elif lang == "move":
            analyzed_langs.add("move")
            edges += _hf_move_edges(ws, rel, src)
        else:
            # UNSUPPORTED language: no parser. A recycle op + a persisted-handle field = an
            # UN-ANALYZED recyclable-handle holder the strict gate must not silently pass.
            body = _csc._strip_strings(_csc._strip_comments(src))
            if _HF_UNSUP_RECYCLE_RE.search(body) and _HF_UNSUP_HOLDER_RE.search(body):
                unanalyzed_examples.append({"file": rel, "language": lang})
    try:
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (ws / ".auditooor" / "state_coupling_handle_freshness.json").write_text(
            scs.json.dumps({
                "schema": "auditooor.state_coupling_handle_freshness.v1",
                "ran": True, "edges": len(edges),
                "analyzed_languages": sorted(analyzed_langs),
                "recyclable_containers": recyclable_containers,
                "unanalyzed_inscope": bool(unanalyzed_examples),
                "unanalyzed_examples": unanalyzed_examples[:8],
            }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        pass
    return edges


# CO-ACCUMULATION Sigma-conservation (conserved-with subtype, additive tier). In a SINGLE
# writer fn a per-key mapping MEMBER cell and an AGGREGATE cell accumulate the SAME delta
# with the SAME sign:
#     position[id][onBehalf].supplyShares += shares;            // member (per-user)
#     market[id].totalSupplyShares       += shares.toUint128(); // aggregate (per-market)
# The invariant is sum(members) == aggregate - the canonical DeFi conservation
# (totalShares == sum supplyShares, totalSupply == sum balances, totalAssets == sum assets);
# every vault / lending / AMM has it. The cross-function conserved-with lane
# (_conservation_edges) STRUCTURALLY misses it: VMF's ledger_write_evidence names the
# function-LOCAL delta (`shares`), NOT the storage cells position[..].supplyShares /
# market[..].totalSupplyShares, and that lane only fires on a cross-fn strict-SUBSET writer.
# The cell names live ONLY in source, so this intra-fn tier reads them straight from source
# (the source-of-truth per the diagnosis). Shape-guarded + advisory (syntactic) confidence;
# upgraded to semantic-ssa ONLY when the dataflow slice links the SAME delta to BOTH cells
# via a distinct storage flow. NEVER auto-promoted on syntactic evidence (the dominant
# conserved-with FP lesson, 2026-07-08: 87 promotable FP edges across 7 ws).

# an ACCUMULATION statement `LHS += RHS;` / `LHS -= RHS;` (NOT ==/<=/>=/!=/*=/-=chain). The
# lvalue char-class allows ident/./[/] so a mapping-member lvalue is captured whole; it holds
# no `(`/`<`/`>` so it can never span across a `require(a <= b)` boundary.
_ACCUM_RE = re.compile(
    r"(?<![=!<>+\-*/%&|^~])"                      # not part of a compound/comparison op
    r"([A-Za-z_][\w.\[\]\s]*?)\s*([+\-])=\s*([^;=][^;]*);")

# a clean co-accumulation DELTA: a single variable, optionally wrapped in cast/getter method
# calls (`shares`, `shares.toUint128()`) - NO binary operators. Requiring a SIMPLE delta is
# the FP guard that keeps `a += x + y` / `a += f(x, y)` out of the same-delta grouping.
_COACCUM_RHS_RE = re.compile(
    r"^\s*([A-Za-z_]\w*)(?:\s*\.\s*[A-Za-z_]\w*\s*\([^()]*\))*\s*$")


def _parse_lvalue(lv: str):
    """(cell_field, index_keys, indexed) for an accumulation lvalue.
      position[id][onBehalf].supplyShares -> ('supplyShares', ['id','onBehalf'], True)
      market[id].totalSupplyShares        -> ('totalSupplyShares', ['id'], True)
      supplyShares[marketId]              -> ('supplyShares', ['marketId'], True)
      total                              -> ('total', [], False)
    The cell is the TRAILING struct field if present (a mapping-of-struct member), else the
    base identifier (a scalar or a mapping-of-scalar)."""
    lv = (lv or "").strip()
    keys = [k.strip() for k in re.findall(r"\[([^\]]*)\]", lv)]
    # Strip the bracket-index contents BEFORE extracting the trailing struct field, so a
    # member-access index key (bal[msg.sender][t]) does not leak its dotted field (.sender)
    # and mislabel the cell. The cell is the trailing struct field OUTSIDE the brackets
    # (position[id][onBehalf].supplyShares -> supplyShares) or the base identifier
    # (bal[msg.sender][t] -> bal). keys stays sourced from the original lvalue.
    dotted = re.findall(r"\.\s*([A-Za-z_]\w*)", re.sub(r"\[[^\]]*\]", "", lv))
    if dotted:
        cell = dotted[-1]
    else:
        m = re.match(r"\s*([A-Za-z_]\w*)", lv)
        if not m:
            return None, [], False
        cell = m.group(1)
    return cell, keys, bool(keys)


def _coaccum_rhs_delta(rhs: str):
    m = _COACCUM_RHS_RE.match(rhs or "")
    return m.group(1) if m else None


def _coaccum_promotes(delta: str, mcell: str, acell: str, lk: set) -> bool:
    """SHARED-DELTA keying: a co-accumulation (member, aggregate) pair promotes to
    semantic-ssa ONLY when the slice witnesses the SAME base delta D flowing into BOTH
    cells - (D, mcell) AND (D, acell) both present in lk. Keying on mere co-write (both
    cells written, any delta) spawns spurious semantic-ssa pairs when the two cells receive
    DIFFERENT deltas (supplyShares<-shares vs totalSupplyAssets<-assets); those stay
    syntactic. lk = _slice_delta_links[writer_fn] = set of (base_delta, cell)."""
    return (delta, mcell) in lk and (delta, acell) in lk


def _fn_accum_cells(src: str) -> dict:
    """fn_name -> set of cells it mutates via accumulation (any delta/sign). Used to find
    PARTIAL-FLUSH violators of a coupled set: a writer that mutates a strict non-empty
    subset of {member, aggregate} desyncs sum(members) from the aggregate."""
    out: dict = {}
    for fn, _ln, body in _csc._functions(src):
        clean = _csc._strip_strings(_csc._strip_comments(body))
        cells: set = set()
        for mm in _ACCUM_RE.finditer(clean):
            cell, _keys, _idx = _parse_lvalue(mm.group(1))
            if cell:
                cells.add(cell)
        if cells:
            out[fn] = cells
    return out


def _fn_conserving_cells(src: str) -> dict:
    """fn_name -> set of cells that are VALUE-CONSERVING (net-zero) WITHIN that fn: a cell
    accumulated with BOTH a += and a -= whose per-delta counts BALANCE exactly (the same
    delta moved in AND out). The canonical case is an ERC20-style member-to-member transfer

        shares[_sender]    -= _sharesAmount;   // -delta on the member cell
        shares[_recipient] += _sharesAmount;   // +delta on the SAME member cell

    which nets ZERO on sum(member) over keys, so a coupled AGGREGATE (totalShares/totalSupply)
    legitimately MUST NOT move - omitting it is CORRECT, not a partial-flush. Used by
    _coaccum_violators to suppress the fleet-RED FP where every OZ/standard ERC20 transfer was
    flagged nviol=1 against a mint/burn-derived member<->aggregate edge.

    PRECISION: a ONE-SIDED mutation (only += or only -=, e.g. a mint or burn of the member)
    is NOT conserving. An UNBALANCED mutation (`c += a; c -= a; c += fee;` -> the + multiset
    {a,fee} != the - multiset {a}) is NOT conserving - it nets a real change, so it stays a
    violator. Conserving requires the + delta-multiset == the - delta-multiset AND both
    non-empty (>=1 increment and >=1 decrement)."""
    out: dict = {}
    for fn, _ln, body in _csc._functions(src):
        clean = _csc._strip_strings(_csc._strip_comments(body))
        plus: dict = {}   # cell -> {delta: count} for += accumulations
        minus: dict = {}  # cell -> {delta: count} for -= accumulations
        for mm in _ACCUM_RE.finditer(clean):
            cell, _keys, _idx = _parse_lvalue(mm.group(1))
            if not cell:
                continue
            delta = _coaccum_rhs_delta(mm.group(3))
            if not delta:
                continue  # only clean single-var deltas count toward net-zero balancing
            bucket = plus if mm.group(2) == "+" else minus
            per = bucket.setdefault(cell, {})
            per[delta] = per.get(delta, 0) + 1
        # net-zero iff, for a cell written with BOTH signs, the +delta multiset EQUALS the
        # -delta multiset (every delta in == same delta out, same count) => sum unchanged.
        conserving = {c for c in (set(plus) & set(minus)) if plus[c] == minus[c]}
        if conserving:
            out[fn] = conserving
    return out


def _coaccum_violators(coupled: set, fn_cells: dict, ws: Path, rel: str,
                       conserving: dict | None = None) -> list[dict]:
    """PARTIAL-FLUSH OMIT-VIOLATOR: for each writer fn touching the coupled set S, if it
    mutates a STRICT NON-EMPTY subset of S it desyncs the Sigma conservation. Emit a
    violator {fn, file, line, mutates, omits}. A writer mutating ALL of S (or none) is not
    a violator. This is what makes a drop-a-member mutation fire (nviol>0).

    EXCLUSION (value-conserving transfer): a writer whose ENTIRE touched coupled subset is
    net-zero VALUE-CONSERVING (see _fn_conserving_cells: += and -= of the same delta on the
    same member cell, e.g. `shares[from]-=amt; shares[to]+=amt;`) is NOT a violator - the sum
    over the member is unchanged, so the omitted AGGREGATE cell legitimately must not move.
    This kills the fleet-RED FP where every ERC20 member-to-member transfer was flagged
    against a mint/burn-derived member<->aggregate edge. A GENUINE partial-flush (a one-sided
    += or -= of the member, or a writer touching the aggregate but omitting the member) is
    NOT conserving and STILL fires."""
    cons = conserving or {}
    viol: list[dict] = []
    for fn, cells in sorted(fn_cells.items()):
        sub = cells & coupled
        if sub and sub != coupled:
            # value-conserving transfer: every coupled cell this writer touches nets to zero,
            # so omitting the aggregate is correct, not a partial-flush -> skip.
            if sub <= cons.get(fn, set()):
                continue
            viol.append({
                "fn": fn,
                "file": rel,
                "line": _fn_def_line(ws, rel, fn) or 0,
                "mutates": sorted(sub),
                "omits": sorted(coupled - sub),
            })
    return viol


def _slice_delta_links(ws: Path) -> dict:
    """norm_fn -> set of (src_var, cell) proven by a DISTINCT storage flow (from_var !=
    to_var) in the dataflow slice. Honestly upgrades a co-accumulation edge to semantic-ssa
    ONLY when the SAME delta is witnessed flowing into BOTH cells. Morpho's slice is
    all-identity hops (distinct_flow_hops=0) -> empty -> co-accumulation stays syntactic."""
    links: dict = {}
    try:
        recs = _df.read_paths(str(ws), skip_degraded=True)
    except Exception:
        return links
    for r in recs:
        for h in (r.get("hops") or []):
            if h.get("via") != "storage":
                continue
            fv, tv = h.get("from_var"), h.get("to_var")
            if fv and tv and str(fv) != str(tv):
                fn = _norm_fn(str(h.get("fn") or (r.get("source") or {}).get("fn") or ""))
                links.setdefault(fn, set()).add((str(fv), str(tv)))
    return links


def _is_value_cell(f: str) -> bool:
    """A co-accumulation cell must be a scalar VALUE/amount (share/supply/asset/balance),
    NOT a rate/price/bound/config/address/snapshot/nonvalue field (reuses the conserved-with
    FP guards)."""
    return not (_is_rate_field(f) or _is_price_field(f) or _is_bound_field(f)
                or _is_addr_or_snapshot_field(f) or _is_nonvalue_field(f))


def _coaccumulation_edges(ws: Path, acct: dict | None = None) -> list[dict]:
    """Aggregate<->member CO-ACCUMULATION conserved-with tier (see block comment). For each
    in-scope Solidity fn, group same-fn accumulations by (delta, sign); a group holding a
    mapping-indexed MEMBER and an AGGREGATE whose index-keys are a STRICT SUBSET of the
    member's yields one conserved-with edge (subtype=co-accumulation). Additive: existing
    edges are untouched; these are appended. Advisory (syntactic) unless the slice links the
    same delta to both cells."""
    if acct is not None:
        acct.setdefault("coaccum_fns_scanned", 0)
        acct.setdefault("coaccum_accum_stmts", 0)
        acct.setdefault("coaccum_edges", 0)
        acct.setdefault("coaccum_examples", [])
    delta_links = _slice_delta_links(ws)
    slice_present = (ws / ".auditooor" / "dataflow_paths.jsonl").is_file()
    edges: list[dict] = []
    seen_pairs: set = set()
    for rel in _csc._load_inscope_files(ws):
        if _is_denied(rel):
            continue
        if _language_of(rel) != "solidity":
            continue  # the intra-fn SSTORE-accumulation shape is Solidity-specific here
        fp = ws / rel
        if not fp.is_file():
            continue
        try:
            src = fp.read_text(errors="replace")
        except OSError:
            continue
        # PARTIAL-FLUSH: per-file fn -> mutated cells, so a co-accum edge can enumerate
        # EVERY writer that touches a strict subset of the coupled set (not just the
        # co-accumulation fn). Built once per file.
        file_fn_cells = _fn_accum_cells(src)
        # per-file fn -> net-zero VALUE-CONSERVING cells (ERC20-style member-to-member
        # transfer): a writer whose whole touched subset is conserving is NOT a partial-flush
        # (the omitted aggregate legitimately must not move). Suppresses the fleet-RED FP.
        file_conserving = _fn_conserving_cells(src)
        for fn, fnline, body in _csc._functions(src):
            clean = _csc._strip_strings(_csc._strip_comments(body))
            groups: dict = {}
            n_stmt = 0
            for mm in _ACCUM_RE.finditer(clean):
                lv, sign, rhs = mm.group(1), mm.group(2), mm.group(3)
                cell, keys, indexed = _parse_lvalue(lv)
                if not cell:
                    continue
                delta = _coaccum_rhs_delta(rhs)
                if not delta:
                    continue
                n_stmt += 1
                groups.setdefault((delta, sign), []).append((cell, tuple(keys), indexed))
            if acct is not None and n_stmt:
                acct["coaccum_fns_scanned"] += 1
                acct["coaccum_accum_stmts"] += n_stmt
            nfn = _norm_fn(fn)
            for (delta, sign), accs in groups.items():
                if len(accs) < 2:
                    continue
                for mcell, mkeys, mindexed in accs:
                    if not mindexed:
                        continue  # the MEMBER must be mapping-indexed
                    mset = set(mkeys)
                    for acell, akeys, _ai in accs:
                        if acell == mcell:
                            continue
                        # AGGREGATE = the non-per-same-key cell: strictly fewer index keys AND
                        # its key-set is a subset of the member's (per-market aggregate over a
                        # per-user member). Equal-depth same-key pairs are a co-indexed
                        # coupling, not aggregate<->member, and are NOT emitted here.
                        if not (len(akeys) < len(mkeys) and set(akeys) <= mset):
                            continue
                        if not (_is_value_cell(mcell) and _is_value_cell(acell)):
                            continue
                        pk = (rel, mcell, acell)
                        if pk in seen_pairs:
                            continue
                        seen_pairs.add(pk)
                        lk = delta_links.get(nfn, set())
                        semantic = _coaccum_promotes(delta, mcell, acell, lk)
                        conf = "semantic-ssa" if semantic else "syntactic"
                        line = _fn_def_line(ws, rel, fn) or fnline
                        # PARTIAL-FLUSH OMIT-VIOLATOR: every writer touching a strict subset
                        # of the coupled set desyncs the Sigma conservation.
                        violators = _coaccum_violators({mcell, acell}, file_fn_cells, ws,
                                                       rel, file_conserving)
                        sid = hashlib.sha1(
                            f"coaccum:{rel}:{mcell}:{acell}".encode()).hexdigest()[:12]
                        e = scs.new_edge(
                            edge_id=sid, language="solidity", kind="conserved-with",
                            cell_a=mcell, cell_b=acell,
                            writers_a=[fn], writers_b=[fn], violators=violators,
                            confidence=conf,
                            evidence={
                                "grounding": ("dataflow-slice+source" if semantic
                                              else "source-accumulation"),
                                "tier": "co-accumulation-sigma-conservation",
                                "subtype": "co-accumulation",
                                "reason": "aggregate<->member co-accumulation of the same delta",
                                "delta": delta, "sign": sign,
                                "member_cell": mcell, "aggregate_cell": acell,
                                "co_accumulation_fn": fn,
                                "co_accumulation_site": f"{rel}:{line}",
                                "persistent_state": True,
                                "slice_present": slice_present,
                                "nviol": len(violators),
                                # advisory unless the slice links the SAME delta to BOTH cells;
                                # a syntactic co-accumulation is NEVER auto-promoted.
                                "promotable": semantic,
                            },
                            obligation=(
                                f"the aggregate cell {acell!r} must equal the sum over keys of "
                                f"its per-key member {mcell!r} (Sigma conservation); every "
                                f"writer accumulating {mcell!r} by a delta must accumulate "
                                f"{acell!r} by the SAME delta and sign - a writer touching one "
                                f"but not the other desyncs sum(members) from the aggregate"))
                        edges.append(e)
                        if acct is not None and len(acct["coaccum_examples"]) < 12:
                            acct["coaccum_examples"].append(
                                {"fn": fn, "file": rel, "member": mcell,
                                 "aggregate": acell, "delta": delta, "confidence": conf})
    if acct is not None:
        acct["coaccum_edges"] = len(edges)
    return edges


# =====================================================================================
# GO CO-WRITE ARM (source-based, degraded-slice-robust). The VMF conserved-with lane
# (_conservation_edges) is BLINDED on every Go target by two compounding drains: (1) the old
# PascalCase _is_nonvalue_field drop (now fixed above) and (2) the pure-calc drain keyed on the
# dataflow slice, which OVER-fires when the Go slice is DEGRADED (sei GOPROXY=off, axelar
# go-dataflow 1800s timeout) so _persisting_fns() is empty and every non-transfer fn is dropped
# as a "pure calculator". This arm reads Go SOURCE directly for the intra-fn CO-WRITE of >=2
# persistent state cells via the cosmos persistence idioms (keeper setter-wrapper `.Set<Cell>(`
# and collection `<Coll>.Set/Insert/Remove/Delete(`), INDEPENDENT of the slice - so a genuine
# coupled-state co-write (createCoins supply/Supply, InitGenesis totalSupply/Supply) emits a
# conserved-with edge even when the Go feeder starved. Advisory (syntactic / needs-fuzz, NEVER
# auto-promoted): the co-write proves the coupling; a cross-fn strict-subset writer is the
# violator. Solidity is untouched (scans only .go files). Feeds its candidate sets into the
# existing intra-fn flush-group detector (partial-flush with an error-return between writes).
_GO_SETTER_WRAP_EXTRACT_RE = re.compile(r"\.\s*Set([A-Z]\w*)\s*\(")
_GO_COLLECTION_WRITE_RE = re.compile(
    r"(?<![.\w])([A-Z]\w*)\s*\.\s*(?:Set|Insert|Remove|Delete)\s*\(")
_GO_FUNC_DEF_RE = re.compile(
    r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?\(", re.M)
# conserved-with is a VALUE-CONSERVATION coupling: at least one endpoint of a co-write pair
# must carry an accounting/amount token, else it is unrelated state co-written in one fn
# (genesis init, tendermint RoundState Proposal/LockedBlock/Validators, config) - the dominant
# Go co-write FP class (measured sei: 455 raw -> mostly consensus/genesis noise). Substring on
# the lowercased cell so Balance/TotalSupply/VaultShares/reserveNav all match.
_GO_VALUE_TOKEN_RE = re.compile(
    r"balance|supply|share|amount|coin|reserve|fund|stake|deposit|debt|collateral"
    r"|reward|(?<![a-z])fee|nav|(?<![a-z])aum|asset|token|mint|burn|liquid|principal"
    r"|interest|escrow|vault|credit|payout|redeem|withdraw|delegat|unbond|bond", re.I)
# genesis / lifecycle / bootstrap / codec fns write MANY unrelated cells at once (bulk init /
# (de)serialization), not a conserved coupling.
_GO_GENESIS_FN_RE = re.compile(
    r"^(?:Init|Export|Default|Register|Validate|Setup|New|Migrate|Build|Load|Marshal"
    r"|Unmarshal|Encode|Decode|Genesis|Prepare|Restore|Import)", re.I)


def _go_is_value_amount(cell: str) -> bool:
    return bool(_GO_VALUE_TOKEN_RE.search(str(cell)))


def _go_cowrite_skip_fn(name: str) -> bool:
    """True for a genesis/lifecycle/config fn whose intra-fn co-writes are bulk init, not a
    conserved coupling (mirrors _conservation_edges' config-fn exclusion for the source lane)."""
    n = name or ""
    return (bool(_GO_GENESIS_FN_RE.match(n)) or _is_config_fn(n)
            or "genesis" in n.lower())  # e.g. prepForZeroHeightGenesis = bulk export


def _go_named_fns(src: str):
    """Yield (name, body) for each Go `func [recv] Name(...) { body }`, brace-balanced over a
    comment/string-stripped source (so a brace inside a literal never mis-closes a body)."""
    clean = _csc._strip_strings(_csc._strip_comments(src))
    for m in _GO_FUNC_DEF_RE.finditer(clean):
        i = clean.find("{", m.end())
        if i < 0:
            continue
        depth, j, guard = 0, i, 0
        while j < len(clean):
            c = clean[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    yield m.group(1), clean[i:j + 1]
                    break
            j += 1
            guard += 1
            if guard > 400000:  # pathological brace-imbalance guard
                break


def _go_cowrite_cells(body: str) -> set:
    """The set of PERSISTENT state cells a Go fn body writes via cosmos persistence idioms: a
    keeper setter-wrapper `.Set<Cell>(` (cell=<Cell>) or a collection `<Coll>.Set/Insert/Remove/
    Delete(` (cell=<Coll>). Value-cell filtered (drops keeper/store/config/handle names via the
    fixed _is_nonvalue_field), min length 3. Body is already comment/string-stripped."""
    cells: set = set()
    for m in _GO_SETTER_WRAP_EXTRACT_RE.finditer(body):
        c = m.group(1)
        if len(c) >= 3 and _is_value_cell(c):
            cells.add(c)
    for m in _GO_COLLECTION_WRITE_RE.finditer(body):
        c = m.group(1)
        if len(c) >= 3 and _is_value_cell(c):
            cells.add(c)
    return cells


def _go_cowrite_edges(ws: Path, acct: dict | None = None) -> list[dict]:
    """Source-based Go co-write conserved-with arm (see header). One advisory conserved-with
    edge per co-written value pair; violators = cross-fn strict-subset writers (a fn writing one
    member but not the other). Slice-independent (robust to a degraded Go feeder). Also runs the
    intra-fn flush-group detector over the source-derived candidate sets. Edges deduped by id."""
    if acct is not None:
        acct.setdefault("go_cowrite_fns_scanned", 0)
        acct.setdefault("go_cowrite_multi_cell_fns", 0)
        acct.setdefault("go_cowrite_pairs", 0)
        acct.setdefault("go_cowrite_edges", 0)
        acct.setdefault("go_cowrite_examples", [])
    fn_cells: dict[tuple, set] = {}       # (rel, fn) -> co-written value cells (>=2)
    cell_writers: dict[str, set] = {}     # cell -> {(rel, fn) writing it} (single or multi)
    for rel in _csc._load_inscope_files(ws):
        if _language_of(rel) != "go" or _is_denied(rel):
            continue
        fp = ws / rel
        if not fp.is_file():
            continue
        try:
            src = fp.read_text(errors="replace")
        except OSError:
            continue
        for name, body in _go_named_fns(src):
            if _go_cowrite_skip_fn(name):
                continue  # genesis/lifecycle/config: bulk init, not a conserved coupling
            cells = _go_cowrite_cells(body)
            if not cells:
                continue
            if acct is not None:
                acct["go_cowrite_fns_scanned"] += 1
            for c in cells:
                cell_writers.setdefault(c, set()).add((rel, name))
            if len(cells) >= 2:
                fn_cells[(rel, name)] = cells
                if acct is not None:
                    acct["go_cowrite_multi_cell_fns"] += 1
    # coupled pairs = every unordered value pair co-written in a single fn.
    pair_cowriters: dict[tuple, set] = {}   # (a,b) -> {(rel,fn) co-writing BOTH}
    pair_file: dict[tuple, str] = {}
    for (rel, fn), cells in fn_cells.items():
        cs = sorted(cells)
        for i in range(len(cs)):
            for k in range(i + 1, len(cs)):
                pk = (cs[i], cs[k])
                pair_cowriters.setdefault(pk, set()).add((rel, fn))
                pair_file.setdefault(pk, rel)
    if acct is not None:
        acct["go_cowrite_pairs"] = len(pair_cowriters)
    edges: list[dict] = []
    slice_present = (ws / ".auditooor" / "dataflow_paths.jsonl").is_file()
    for (a, b), cowriters in sorted(pair_cowriters.items()):
        # VALUE-CONSERVATION gate: >=1 endpoint must be an accounting/amount cell, else the
        # co-write is unrelated state (consensus RoundState / config / lifecycle), not a
        # conserved-with coupling. This is the precision filter that cuts the FP flood.
        if not (_go_is_value_amount(a) or _go_is_value_amount(b)):
            continue
        rel = pair_file[(a, b)]
        wa = cell_writers.get(a, set())
        wb = cell_writers.get(b, set())
        # a violator writes exactly ONE member of the pair (strict, non-empty subset).
        both = {rf for rf in (wa | wb)
                if {a, b} <= fn_cells.get(rf, set())}
        violators = []
        for rf in sorted((wa | wb) - both):
            vrel, vfn = rf
            writes_a = rf in wa
            violators.append({
                "fn": vfn, "file": vrel, "line": _fn_def_line(ws, vrel, vfn) or 0,
                "mutates": [a] if writes_a else [b],
                "omits": [b] if writes_a else [a]})
            if len(violators) >= 12:
                break
        cowr_fns = sorted({fn for _r, fn in cowriters})
        sid = hashlib.sha1(f"go-cowrite:{a}:{b}".encode()).hexdigest()[:12]
        e = scs.new_edge(
            edge_id=sid, language="go", kind="conserved-with",
            cell_a=a, cell_b=b,
            writers_a=sorted({fn for _r, fn in wa}),
            writers_b=sorted({fn for _r, fn in wb}),
            violators=violators, confidence="syntactic",
            evidence={
                "grounding": "go-source-cowrite",
                "tier": "go-co-write-conservation",
                "subtype": "go-co-write",
                "reason": "two persistent state cells written together in one fn",
                "cowrite_fns": cowr_fns[:12],
                "cowrite_site": f"{rel}",
                "persistent_state": True,
                "slice_present": slice_present,
                "nviol": len(violators),
                # advisory-first: source-detected co-write proves the coupling, but the
                # desync-is-exploitable leg needs a probe/fuzz - NEVER auto-promoted (the
                # dominant conserved-with FP lesson).
                "verdict": "needs-fuzz",
                "advisory": True,
                "auto_credit": False,
                "promotable": False,
            },
            obligation=(
                f"the persistent state cells {a!r} and {b!r} are co-written in "
                f"{', '.join(cowr_fns[:3]) or '?'} (they must move together); a writer that "
                f"mutates one but not the other desyncs the coupling"))
        edges.append(e)
        if acct is not None and len(acct["go_cowrite_examples"]) < 12:
            acct["go_cowrite_examples"].append(
                {"pair": [a, b], "cowrite_fns": cowr_fns[:4], "file": rel,
                 "nviol": len(violators)})
    # intra-fn flush-group (partial-flush: non-atomic co-write with an error-return between the
    # two persistent writes) over the SAME source-derived candidate sets.
    field_writers = {c: {fn for _r, fn in w} for c, w in cell_writers.items()}
    flush = _flush_group_edges(
        ws, [(cells, rel, fn) for (rel, fn), cells in fn_cells.items()], field_writers)
    # dedup by edge_id (a flush edge may coincide with a co-write edge id space; keep first).
    seen_ids = {e["edge_id"] for e in edges}
    for fe in flush:
        if fe["edge_id"] not in seen_ids:
            seen_ids.add(fe["edge_id"])
            edges.append(fe)
    if acct is not None:
        acct["go_cowrite_edges"] = len(edges)
        acct["go_cowrite_flush_edges"] = len(flush)
    return edges


# =====================================================================================
# RUST CO-WRITE ARM (source-based). Rust workspaces (axelar tofn/tofnd ecdsa, near-intents,
# ...) had ZERO SCG coverage: no Rust producer existed. A Rust coupling is fields mutated
# TOGETHER in one fn - `self.X = ..`, a `<map>.insert(..)`, or a struct LITERAL co-construction
# `Type { f1, f2, .. }` (the namesake tofn `KeyPair { signing_key, encoded_verifying_key }`:
# the signing key and its encoded verifying key MUST correspond). One advisory conserved-with
# edge per co-mutated field pair; violators = a sibling fn mutating one field but not the other.
# Advisory (syntactic / needs-fuzz), NEVER auto-promoted (no Rust def-use slice to ground it).
# FAIL-LOUD: if in-scope Rust is PRESENT but no co-write edge survives, a blind marker edge is
# emitted so a 0 never silently reads as clean (rule (3)).
_RUST_FUNC_DEF_RE = re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(", re.M)
_RUST_SELF_ASSIGN_RE = re.compile(r"(?<![.\w])self\s*\.\s*([A-Za-z_]\w*)\s*(?<![=!<>])=(?!=)")
_RUST_INSERT_RE = re.compile(
    r"(?<![.\w])(?:self\s*\.\s*)?([A-Za-z_]\w*)\s*\.\s*insert\s*\(")
_RUST_STRUCT_LIT_RE = re.compile(r"(?<![.\w])([A-Z]\w*)\s*\{")
# fields that are structural noise, not coupled state (phantom markers / private padding).
_RUST_NOISE_FIELD = frozenset({"phantom", "_phantom", "marker", "_marker", "phantomdata"})
# DTO / message / config / response TYPE names: a struct-literal co-construction of these is a
# transient message/config value, not a persistent coupled STATE record (cosmwasm BankMsg /
# CacheOptions / QueryResponse). Suffix-matched on the literal's type name.
_RUST_DTO_TYPE_RE = re.compile(
    r"(?:Msg|Message|Response|Request|Reply|Options|Config|Params|Info|Args|Builder|Case"
    r"|Error|Event|Query|Cmd|Command|Dto|Output|Input|Result|Data|Meta|Header|Ctx"
    r"|Context|Env|Report|Spec|Descriptor|Descriptor|Test)$")
# test / fixture fn names whose co-writes are test vectors, not production state.
_RUST_TEST_FN_RE = re.compile(
    r"test|known_vectors|dummy|mock|bench|proptest|fuzz|fixture|sample|example", re.I)


def _rust_is_test_fn(name: str) -> bool:
    return bool(_RUST_TEST_FN_RE.search(name or ""))


def _rust_strip_test_modules(src: str) -> str:
    """Blank out `#[cfg(test)] mod .. { .. }` and `mod tests { .. }` blocks so test-fixture
    co-writes (TestCase struct literals, golden-vector builders) never seed a coupling edge."""
    out = src
    for rx in (re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*mod\s+\w+\s*\{"),
               re.compile(r"\bmod\s+tests\s*\{")):
        while True:
            m = rx.search(out)
            if not m:
                break
            i = out.find("{", m.start())
            depth, j, guard = 0, i, 0
            while j < len(out):
                c = out[j]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
                guard += 1
                if guard > 4000000:
                    break
            out = out[:m.start()] + " " + out[j + 1:]
    return out


def _rust_named_fns(src: str):
    """Yield (name, body) for each Rust `fn Name(...) { body }`, brace-balanced over a
    comment/string-stripped source."""
    clean = _csc._strip_strings(_csc._strip_comments(src))
    for m in _RUST_FUNC_DEF_RE.finditer(clean):
        i = clean.find("{", m.end())
        if i < 0:
            continue
        depth, j, guard = 0, i, 0
        while j < len(clean):
            c = clean[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    yield m.group(1), clean[i:j + 1]
                    break
            j += 1
            guard += 1
            if guard > 400000:
                break


def _rust_field_name(seg: str) -> str | None:
    seg = seg.strip()
    if not seg or seg.startswith(".."):   # ..spread base
        return None
    m = re.match(r"([A-Za-z_]\w*)\s*:", seg)   # `field: value`
    if m:
        return m.group(1)
    m = re.match(r"([A-Za-z_]\w*)\s*$", seg)   # shorthand `field`
    return m.group(1) if m else None


def _rust_top_level_fields(inner: str) -> list:
    """Top-level field names of a struct-literal body (comma-split at bracket depth 0)."""
    fields, seg, depth = [], "", 0
    for ch in inner:
        if ch in "([{":
            depth += 1
            seg += ch
        elif ch in ")]}":
            depth -= 1
            seg += ch
        elif ch == "," and depth == 0:
            f = _rust_field_name(seg)
            if f:
                fields.append(f)
            seg = ""
        else:
            seg += ch
    f = _rust_field_name(seg)
    if f:
        fields.append(f)
    return fields


def _rust_struct_lit_field_sets(body: str) -> list:
    """[(Type, {field,...})] for each struct literal `Type { .. }` with >=2 top-level fields."""
    out = []
    for m in _RUST_STRUCT_LIT_RE.finditer(body):
        ty = m.group(1)
        if _RUST_DTO_TYPE_RE.search(ty):
            continue  # transient message/config/response DTO, not persistent coupled state
        i = m.end() - 1  # at '{'
        depth, j, guard = 0, i, 0
        while j < len(body):
            c = body[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
            guard += 1
            if guard > 200000:
                break
        inner = body[i + 1:j]
        # a struct literal has `field: value` or shorthand `field`; a bare code block (match
        # arm / closure body) has neither at top level -> yields <2 fields -> skipped.
        fields = [f for f in _rust_top_level_fields(inner)
                  if f.lower() not in _RUST_NOISE_FIELD and len(f) >= 2]
        if len(set(fields)) >= 2:
            out.append((ty, set(fields)))
    return out


def _rust_fn_cowrite_sets(body: str) -> list:
    """Co-mutation cell SETS in one Rust fn body: (1) each struct-literal co-construction with
    >=2 fields, (2) the set of >=2 distinct `self.X = ` assigned fields, (3) the set of >=2
    distinct `<map>.insert(` targets. Returns a list of frozensets (>=2 cells each)."""
    sets: list = []
    for _ty, fields in _rust_struct_lit_field_sets(body):
        sets.append(frozenset(fields))
    self_fields = {m.group(1) for m in _RUST_SELF_ASSIGN_RE.finditer(body)
                   if m.group(1).lower() not in _RUST_NOISE_FIELD and len(m.group(1)) >= 2}
    if len(self_fields) >= 2:
        sets.append(frozenset(self_fields))
    inserts = {m.group(1) for m in _RUST_INSERT_RE.finditer(body)
               if m.group(1).lower() not in _RUST_NOISE_FIELD and len(m.group(1)) >= 2}
    if len(inserts) >= 2:
        sets.append(frozenset(inserts))
    return sets


def _rust_cowrite_edges(ws: Path, acct: dict | None = None) -> list[dict]:
    """Source-based Rust co-write conserved-with arm (see header). One advisory conserved-with
    edge per co-mutated field pair; violators = a sibling fn writing one member but not the
    other. FAIL-LOUD blind marker when in-scope Rust is present but no edge survives."""
    if acct is not None:
        acct.setdefault("rust_present", False)
        acct.setdefault("rust_cowrite_fns_scanned", 0)
        acct.setdefault("rust_cowrite_multi_cell_fns", 0)
        acct.setdefault("rust_cowrite_edges", 0)
        acct.setdefault("rust_cowrite_examples", [])
    fn_cells: dict[tuple, set] = {}       # (rel, fn) -> union of co-mutated cells
    cell_writers: dict[str, set] = {}     # cell -> {(rel, fn)}
    pair_cowriters: dict[tuple, set] = {}
    pair_file: dict[tuple, str] = {}
    rust_present = False
    for rel in _csc._load_inscope_files(ws):
        if _language_of(rel) != "rust" or _is_denied(rel):
            continue
        fp = ws / rel
        if not fp.is_file():
            continue
        rust_present = True
        try:
            src = fp.read_text(errors="replace")
        except OSError:
            continue
        src = _rust_strip_test_modules(src)
        for name, body in _rust_named_fns(src):
            if _rust_is_test_fn(name):
                continue  # test/fixture fn: co-writes are test vectors, not production state
            sets = _rust_fn_cowrite_sets(body)
            if not sets:
                continue
            if acct is not None:
                acct["rust_cowrite_fns_scanned"] += 1
            union: set = set()
            for S in sets:
                union |= set(S)
                cs = sorted(S)
                for i in range(len(cs)):
                    for k in range(i + 1, len(cs)):
                        pk = (cs[i], cs[k])
                        pair_cowriters.setdefault(pk, set()).add((rel, name))
                        pair_file.setdefault(pk, rel)
            if union:
                fn_cells[(rel, name)] = union
                for c in union:
                    cell_writers.setdefault(c, set()).add((rel, name))
                if len(union) >= 2 and acct is not None:
                    acct["rust_cowrite_multi_cell_fns"] += 1
    if acct is not None:
        acct["rust_present"] = rust_present
    edges: list[dict] = []
    for (a, b), cowriters in sorted(pair_cowriters.items()):
        rel = pair_file[(a, b)]
        wa = cell_writers.get(a, set())
        wb = cell_writers.get(b, set())
        both = {rf for rf in (wa | wb) if {a, b} <= fn_cells.get(rf, set())}
        violators = []
        for rf in sorted((wa | wb) - both):
            vrel, vfn = rf
            writes_a = rf in wa
            violators.append({
                "fn": vfn, "file": vrel, "line": _fn_def_line(ws, vrel, vfn) or 0,
                "mutates": [a] if writes_a else [b],
                "omits": [b] if writes_a else [a]})
            if len(violators) >= 12:
                break
        cowr_fns = sorted({fn for _r, fn in cowriters})
        sid = hashlib.sha1(f"rust-cowrite:{rel}:{a}:{b}".encode()).hexdigest()[:12]
        edges.append(scs.new_edge(
            edge_id=sid, language="rust", kind="conserved-with",
            cell_a=a, cell_b=b,
            writers_a=sorted({fn for _r, fn in wa}),
            writers_b=sorted({fn for _r, fn in wb}),
            violators=violators, confidence="syntactic",
            evidence={
                "grounding": "rust-source-cowrite",
                "tier": "rust-co-write-conservation",
                "subtype": "rust-co-write",
                "reason": "two struct/self/map fields mutated together in one fn",
                "cowrite_fns": cowr_fns[:12], "cowrite_site": rel,
                "persistent_state": True, "slice_present": False,
                "nviol": len(violators), "verdict": "needs-fuzz",
                "advisory": True, "auto_credit": False, "promotable": False,
            },
            obligation=(
                f"the fields {a!r} and {b!r} are mutated together in "
                f"{', '.join(cowr_fns[:3]) or '?'} (coupled state); a fn that mutates one "
                f"but not the other desyncs the coupling")))
        if acct is not None and len(acct["rust_cowrite_examples"]) < 12:
            acct["rust_cowrite_examples"].append(
                {"pair": [a, b], "cowrite_fns": cowr_fns[:4], "file": rel})
    if acct is not None:
        acct["rust_cowrite_edges"] = len(edges)
    # FAIL-LOUD: in-scope Rust present but no co-write edge -> blind marker so a 0 is never
    # silently read as a clean/complete Rust surface (rule (3), anti-silent-suppression).
    if rust_present and not edges:
        edges.append(scs.new_edge(
            edge_id=hashlib.sha1(b"rust-cowrite-blind").hexdigest()[:12],
            language="rust", kind="conserved-with",
            cell_a="<rust-co-write-arm>", cell_b="<blind>",
            writers_a=[], writers_b=[], violators=[], confidence="heuristic",
            evidence={
                "status": "blind",
                "degrade_reason": "in-scope Rust present but no struct/self/map co-write "
                                  "pair found - either genuinely coupling-free (crypto "
                                  "primitives) or an idiom this arm does not parse; a 0 is "
                                  "NOT proven-clean",
                "tier": "rust-co-write-conservation", "advisory": True,
                "auto_credit": False, "promotable": False, "persistent_state": False,
                "slice_present": False},
            obligation="fail-loud marker: Rust co-write arm produced 0 real edges over "
                       "present in-scope Rust - review before trusting the 0"))
    return edges


def _precision_gate(ws: Path, raw: list[dict]):
    """P2a: drop measured FP classes BEFORE any downstream consumer sees an edge.
    Rules (workflow wf_1473a23c measured sei ~1/10, ssv-network 0/9 real without it):
      1. denylist path filter (vendored / test / sim files).
      2. persistent-state grounding: when a def-use slice exists, BOTH cells MUST be
         storage cells; else DROP (kills param / local / value-receiver / plural-
         collision FPs in one check). Without a slice, keep as syntactic-advisory.
      3. anchor violators[].line to the real storage write site of the mutated cell.
      4. promotable = persistent AND writers non-empty - so a tier=regex edge with
         EMPTY writers is NEVER promotable (advisory WARN only, never gate/queue-fed).
         confidence stays 'syntactic' until P2b fills writers via closure.
    """
    storage_cells, sites = _storage_facts(ws)
    slice_present = (ws / ".auditooor" / "dataflow_paths.jsonl").is_file()
    kept: list[dict] = []
    stats = {"deny": 0, "nonpersistent": 0, "persistent": 0, "advisory": 0,
             "slice_present": slice_present}
    for e in raw:
        vf = (e["violators"][0]["file"] if e.get("violators") else
              e.get("writer_file", ""))
        if _is_denied(vf):
            stats["deny"] += 1
            continue
        persistent = e["cell_a"] in storage_cells and e["cell_b"] in storage_cells
        if slice_present and not persistent:
            stats["nonpersistent"] += 1
            continue
        # anchor the violator line to the real storage write of the mutated cell
        if e.get("violators") and e["cell_b"] in sites and sites[e["cell_b"]]:
            f, l, fn = sites[e["cell_b"]][0]
            if l:
                e["violators"][0]["line"] = l
                if fn:
                    e["violators"][0]["fn"] = fn
        # P2b: fill def-use-grounded writer sets (closure writers) from the slice
        e["writers_a"] = _writers_from_sites(e["cell_a"], sites)
        e["writers_b"] = _writers_from_sites(e["cell_b"], sites)
        # P2b: a monotonic-counter derived coupling is really an ORDERING coupling
        if e["kind"] == "derived-from" and _is_ordering_pair(e["cell_a"], e["cell_b"]):
            e["kind"] = "ordering"
            e["impact_class"] = scs.KIND_IMPACT["ordering"]
        e["evidence"]["persistent_state"] = persistent
        e["evidence"]["slice_present"] = slice_present
        e["evidence"]["promotable"] = bool(
            persistent and (e["writers_a"] or e["writers_b"]))
        kept.append(e)
        if persistent:
            stats["persistent"] += 1
        else:
            stats["advisory"] += 1
    return kept, stats


def _emit(ws: Path | None, single: Path | None, co_indexed: bool) -> int:
    edges: list[dict] = []
    if single:
        rows = _csc._rows_for_source(single.read_text(errors="replace"),
                                     str(single), co_indexed=co_indexed)
        edges = [_row_to_edge(r, _language_of(str(single))) for r in rows]
    elif ws:
        raw = []
        fresh = []
        for rel in _csc._load_inscope_files(ws):
            fp = ws / rel
            if fp.is_file():
                src = fp.read_text(errors="replace")
                rows = _csc._rows_for_source(src, rel, co_indexed=co_indexed)
                raw += [_row_to_edge(r, _language_of(rel)) for r in rows]
                fresh += _freshness_edges(src, rel)
        edges, stats = _precision_gate(ws, raw)
        # P2b: conserved-with edges from the VMF ledger analysis (semantic-ssa,
        # persistent by construction) - appended after the regex precision gate.
        cw_acct: dict = {}
        conserved = _conservation_edges(ws, acct=cw_acct)
        # 10th kind: cross-domain (internal share/supply <-> external asset balance).
        cross_domain = _cross_domain_conservation_edges(ws, acct=cw_acct)
        # CO-ACCUMULATION Sigma-conservation (conserved-with subtype): intra-fn aggregate<->
        # member co-accumulation of the SAME delta (position[..].supplyShares +=shares AND
        # market[..].totalSupplyShares +=shares). Source-read; additive (appended last so the
        # pre-existing edge byte-stream is unchanged).
        coaccum = _coaccumulation_edges(ws, acct=cw_acct)
        # P8: freshness-coupled edges (asymmetric staleness enforcement) - source-
        # detected, bypass storage grounding (the clock endpoint has no on-chain writer).
        edges += conserved + cross_domain + fresh + coaccum
        # GO CO-WRITE (source-based, degraded-slice-robust) + RUST CO-WRITE arms - the
        # flagship co-write/conserved-with coverage the VMF lane misses on every Go target
        # (PascalCase drop + degraded-slice pure-calc drain) and had ZERO Rust producer for.
        # Additive + deduped by edge_id vs everything already emitted so the pre-existing
        # (Sol/VMF) byte-stream is preserved.
        _existing_ids = {e["edge_id"] for e in edges}
        go_cowrite = _go_cowrite_edges(ws, acct=cw_acct)
        rust_cowrite = _rust_cowrite_edges(ws, acct=cw_acct)
        for _e in go_cowrite + rust_cowrite:
            if _e["edge_id"] not in _existing_ids:
                _existing_ids.add(_e["edge_id"])
                edges.append(_e)
        # 11th kind: INTERRUPTION (cross-fn two-phase split) - advisory-first, OFF by default
        # (a DEDICATED env). needs-fuzz verdict, NO auto-credit. Dedup emitted hits vs the
        # existing flush-group edges already in `edges` (A1 boundary, not a covered_by re-derive).
        interruption = []
        if os.environ.get("SCG_INTERRUPTION") not in (None, "", "0", "no", "false"):
            _flush_existing = [e for e in edges if e.get("kind") == "flush-group"]
            interruption = _interruption_edges(ws, flush_edges=_flush_existing)
            edges += interruption
        # A12: FRESHNESS-COUPLED-TO-SHARED-CURSOR (cross-module cursor snapshot desync) -
        # advisory-first, OFF by default (SCG_SHARED_CURSOR). needs-fuzz verdict, NO auto-credit.
        # Dedup emitted hits vs the external-clock freshness edges already in `fresh`.
        shared_cursor = []
        if os.environ.get("SCG_SHARED_CURSOR") not in (None, "", "0", "no", "false"):
            shared_cursor = _freshness_shared_cursor_edges(ws, fresh_edges=fresh)
            edges += shared_cursor
        # 14th kind: STALE-HANDLE-AFTER-RECYCLE (R1 handle-freshness arm) - advisory-first, OFF by
        # default (SCG_HANDLE_FRESHNESS). needs-fuzz verdict, NO auto-credit. prior_edges carries the
        # A12 shared-cursor edges (already appended) + the external-clock fresh edges for dedup. When
        # OFF, write a FRESH default accounting sidecar so a stale enforce-run un-analyzed flag from a
        # prior pass can never linger (the SCG is regenerated each --emit; so is its sidecar).
        handle_freshness = []
        if os.environ.get("SCG_HANDLE_FRESHNESS") not in (None, "", "0", "no", "false"):
            handle_freshness = _handle_freshness_edges(ws, prior_edges=edges + fresh)
            edges += handle_freshness
        else:
            try:
                (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
                (ws / ".auditooor" / "state_coupling_handle_freshness.json").write_text(
                    scs.json.dumps({"schema": "auditooor.state_coupling_handle_freshness.v1",
                                    "ran": False, "edges": 0, "unanalyzed_inscope": False,
                                    "unanalyzed_examples": []}, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
            except OSError:
                pass
        # cross-domain BLIND-SPOT WARN: a 0-edge cross-domain result is NOT cited-clean
        # when share-marker movers exist that the struct-field lane could not assess.
        if cw_acct.get("cross_domain_assessment_complete") is False:
            um = cw_acct.get("cross_domain_unassessable_share_movers", [])
            print(
                f"[state-coupling-graph] WARN cross-domain-conservation INCOMPLETE: "
                f"{len(um)} share-marker mover(s) change supply via an external marker/bank "
                f"coin (empty ledger field) so the struct-field lane could NOT assess their "
                f"asset-pairing: {um[:8]}. A 0-edge result here is INCOMPLETE, NOT proven-"
                f"clean - probe each for a shares-vs-underlying (or shares-vs-TotalShares "
                f"dual-accounting) divergence. accounting -> "
                f".auditooor/state_coupling_conserved_accounting.json", file=sys.stderr)
        n = scs.write_edges(ws, edges)
        # Persist the conserved-with exclusion accounting so the 0/N drain is auditable
        # (a downstream completeness gate / operator can review WHY, not trust a silent 0).
        try:
            acct_path = ws / ".auditooor" / "state_coupling_conserved_accounting.json"
            acct_path.parent.mkdir(parents=True, exist_ok=True)
            acct_path.write_text(scs.json.dumps(cw_acct, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
        except OSError:
            pass
        promotable = sum(1 for e in edges if e.get("evidence", {}).get("promotable"))
        print(f"[state-coupling-graph] {n} edge(s) -> {scs.edges_path(ws)} "
              f"(persistent-grounded {stats['persistent']}, conserved-with "
              f"{len(conserved)}, go-co-write {len(go_cowrite)}, rust-co-write "
              f"{len(rust_cowrite)}, co-accumulation {len(coaccum)}, freshness {len(fresh)}, "
              f"interruption {len(interruption)} (advisory/needs-fuzz), "
              f"shared-cursor {len(shared_cursor)} (advisory/needs-fuzz), "
              f"handle-freshness {len(handle_freshness)} (advisory/needs-fuzz), "
              f"promotable {promotable}, "
              f"syntactic-advisory {stats['advisory']}; dropped {stats['deny']} "
              f"denylisted + {stats['nonpersistent']} non-persistent-state; "
              f"slice_present={stats['slice_present']})", file=sys.stderr)
        # THE anti-silent-suppression signal (this session's lesson): a mega-capability
        # that EXCLUSION-DRAINS to 0 is a telltale sign - make it LOUD, never invisible.
        if cw_acct.get("no_subset_writer"):
            # distinguish a TRUE atomic-writer 0 from a 0 caused by the persistent-cell
            # resolution being UNAVAILABLE (slice present but its fn/var vocabulary does
            # not overlap the VMF value-movers - measured on NUVA: 861 storage hops, all
            # OZ-library boilerplate, 0 overlap with the 73 vault value-movers). The
            # latter means the cross-function class is UNPROVABLE here, not proven-absent.
            resolved = cw_acct.get("slice_resolution_pairs", 0)
            slice_note = (
                "persistent-cell resolution grounded the sets (partial-flush truly absent)"
                if resolved else
                "persistent-cell resolution UNAVAILABLE (0 VMF names resolved to a storage "
                "cell - local-name fallback only; the cross-function class is UNPROVABLE "
                "via this lane on this workspace, NOT proven-absent)")
            print(
                f"[state-coupling-graph] WARN conserved-with drained to 0 edges despite "
                f"{cw_acct.get('surviving_conserved_sets', 0)} surviving conserved set(s) "
                f"(from {cw_acct.get('multi_field_movers', 0)} multi-field value-mover(s); "
                f"excluded config-fn={cw_acct.get('excluded_config_fn', 0)}, "
                f"collapsed<2={cw_acct.get('sets_collapsed_below_2', 0)}; "
                f"slice_resolution_pairs={resolved}). REASON: no cross-function strict-"
                f"subset writer - {slice_note}. Re-probe the surviving set(s) for a "
                f"partial-update path before trusting it; accounting -> "
                f".auditooor/state_coupling_conserved_accounting.json", file=sys.stderr)
        elif cw_acct.get("surviving_local_pipeline_sets", 0) > 0 and cw_acct.get("surviving_conserved_sets", 0) == 0:
            # NUVA 2026-07-09: the only surviving set(s) are function-local value
            # PIPELINES (each cell a call-return local, not persistent storage) - correctly
            # not promoted, and provably NOT a partial-flush surface (no storage to desync).
            # QUIET informational note, NOT a re-probe/over-exclusion cry-wolf.
            print(
                f"[state-coupling-graph] conserved-with: "
                f"{cw_acct.get('surviving_local_pipeline_sets', 0)} surviving set(s) are "
                f"function-local value-pipelines (all cells call-return locals, no declared "
                f"state var), correctly not promoted - not a partial-flush surface; 0 "
                f"persistent conserved set(s). e.g. "
                f"{(cw_acct.get('surviving_local_pipeline_examples') or [{}])[0].get('fn', '?')}",
                file=sys.stderr)
        elif cw_acct.get("multi_field_movers", 0) > 0 and cw_acct.get("surviving_conserved_sets", 0) == 0:
            print(
                f"[state-coupling-graph] WARN conserved-with: all "
                f"{cw_acct.get('multi_field_movers', 0)} multi-field value-mover(s) were "
                f"EXCLUDED to 0 surviving set(s) (config-fn={cw_acct.get('excluded_config_fn', 0)}, "
                f"field-collapsed<2={cw_acct.get('sets_collapsed_below_2', 0)}, "
                f"local-pipeline={cw_acct.get('surviving_local_pipeline_sets', 0)}). If the "
                f"exclusions are over-broad this hides a real coupling - review "
                f".auditooor/state_coupling_conserved_accounting.json", file=sys.stderr)
        return 0
    for e in edges:
        print(scs.json.dumps(e, sort_keys=True))
    print(f"[state-coupling-graph] {len(edges)} edge(s)", file=sys.stderr)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", type=Path)
    ap.add_argument("--file", type=Path)
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--co-indexed", action="store_true")
    a = ap.parse_args(argv)
    if a.emit:
        return _emit(a.workspace, a.file, a.co_indexed)
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
