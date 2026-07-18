#!/usr/bin/env python3
"""consensus-map-order-return-screen.py - GEN-D, the CONSENSUS-NONDETERMINISTIC
RETURN-ORDERING screen (lang-intrinsic layer = go-consensus).

GENERAL LOGIC (a consensus-safety class, never a numeric-value SHAPE). Go
`for k := range someMap { ... }` iterates in a RANDOMIZED order. If the loop body
APPENDS to a slice and that slice becomes (directly or transitively) a
CONSENSUS-SERIALIZED RETURN, different validators build the slice in DIFFERENT
orders -> divergent AppHash -> chain halt (a consensus-safety bug). This is the
canonical Cosmos "iterate a map, forget to sort" liveness/consensus footgun.

FIRE when a range-over-map loop appends to a plain slice AND that slice reaches a
consensus-relevant return/serialization sink WITHOUT a dominating deterministic
sort (sort.Slice / sort.SliceStable / sort.Strings / sort.Sort / slices.Sort) on
that slice before the sink.

Consensus-return sinks (each classified):
  * validator-update   - a []abci.ValidatorUpdate returned from EndBlock/EndBlocker
  * abci-event         - a []abci.Event / sdk.Events list returned to the ABCI layer
  * proposal-tx-order  - a Prepare/ProcessProposal tx-ordering slice
  * genesis-export     - a slice assembled into an Init/ExportGenesis return
  * denom-slice        - a []string denom/address slice returned from a Keeper method
  * keeper-return      - any other Keeper method whose []T return is store-/ABCI-fed

FP-CONTROL (not every range-over-map; do NOT spray). The slice must REACH a
consensus-relevant return AND there must be NO dominating sort before the sink.
SILENCE:
  (a) a `sort.Slice/SliceStable/Strings/Sort/slices.Sort(<slice>)` after the loop
      and before the sink (the dominating-sort suppressor);
  (b) iterating a PRE-SORTED key slice (`keys := maps.Keys(m); sort.Strings(keys);
      for _, k := range keys {...}`) instead of the map directly - this is a slice
      range, never matches the map-range predicate;
  (c) the slice is used only for LOGGING / metrics / a local non-consensus
      computation / a test - it never reaches a return, so reaches_return is False;
  (d) the append target is a keyed map write (`m[k] = append(...)`) - an
      order-INVARIANT distinct-key accumulation, not a returned ordered slice; only
      a plain-identifier slice accumulator fires.
If the sink cannot be CONFIRMED consensus-returned (denom-slice / keeper-return),
the row is tagged severity='medium' not 'high'. The strong EndBlock /
ValidatorUpdate / Event / genesis-export shapes are 'high'.

DEDUP / distinctness (per dispatch brief):
  * consensus-write-determinism-census (go-detector-runner G-CENSUS) screens the
    map-range -> store.Set / KVStore WRITE sink (nondeterministic STATE WRITE), NOT
    the ABCI/genesis RETURN-SLICE sink. GEN-D adds the return-slice sink.
  * G4 / the nondeterminism-value screen flags nondeterministic VALUES
    (time.Now / rand / float in consensus), NOT map-iteration ORDER into a returned
    slice.
  GEN-D = the map-range-APPEND-to-a-consensus-RETURN-slice-WITHOUT-a-sort JOIN; a
  site that reduces to a store-write sink or a nondeterministic-value source is
  dropped as overlap.

  UPGRADE/EXTENSION DECISION (cited): the census lives INLINE in
  tools/go-detector-runner.py (`_detect_consensus_write_determinism_census`), not
  as a standalone tool, and its sink is HARD-WIRED to KVStore writes via
  `_gcensus_enumerate_writes` (there is NO pluggable sink registry to extend). So
  GEN-D is a SIBLING standalone screen that shares the census's map-range detection
  CONCEPT (re-implemented self-contained here, exactly as gas-repricing-fragility-
  screen.py is self-contained) while targeting the disjoint ABCI/genesis
  return-slice sink. No behaviour of the census changes.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False; the tool exits 0 by default. The opt-in env
AUDITOOOR_CONSENSUS_MAP_ORDER_RETURN_STRICT (or --strict) raises the exit code
when a fired row exists.

Excludes machine-generated (.pb.go/.pulsar.go + "DO NOT EDIT"), test, mock, sim
and vendored code via the shared exclusion libs.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/
                     consensus_map_order_return_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single .go file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a fired row exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.consensus_map_order_return_hypotheses.v1"
_SIDE_NAME = "consensus_map_order_return_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_CONSENSUS_MAP_ORDER_RETURN_STRICT"
_CAPABILITY = "GEN_D"

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# --- shared exclusion (reuse, never rebuild) --------------------------------
try:  # tools/lib/synthetic_target_exclusion.py
    from lib.synthetic_target_exclusion import (  # noqa: E402
        is_chimera_mutation_harness_path,
        is_codegen_path,
        is_test_target_path,
    )
except Exception:  # pragma: no cover - degrade to no-op if lib unavailable
    def is_test_target_path(_p):  # type: ignore
        return False

    def is_codegen_path(_p, workspace=None):  # type: ignore
        return False

    def is_chimera_mutation_harness_path(_p):  # type: ignore
        return False


_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "certora", "simulation", "testdata",
              "mocks", "mock", "artifacts", "chimera_harnesses"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|testutil|testonly|testhelper|test_fixtures|mock|mocks|"
    r"benches|benchmarks?|examples|fixtures|simulation|simapp|testdata|poc|"
    r"chimera_harnesses)(/|$)")
_CODEGEN_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)

# OFF-CONSENSUS node subsystems (mirrors go-detector-runner's
# _GCENSUS_OFFCONSENSUS_PATH): tendermint/cometbft-internal RPC, event pubsub,
# mempool, p2p, statesync/blocksync, light-client, privval and the tx indexer are
# NOT the deterministic app state machine - a map-ordered slice they return feeds
# an RPC response or a subscription match, never the block AppHash, so it cannot
# cause a consensus halt. Exclude these paths from the consensus-return gate.
_OFFCONSENSUS_PATH = re.compile(
    r"(^|/)(rpc|coretypes|jsonrpc|pubsub|mempool|p2p|statesync|blocksync|"
    r"blockchain|fastsync|light|privval|indexer|inspect|proxy|libs)(/|$)", re.I)


# ============================================================================
# comment / string masking (Go uses C-ish comments).
# ============================================================================
def _mask_comments(text: str) -> str:
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = in_raw = False
    quote = ""
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                in_block = False
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif in_str:
            out.append(" ")
            if c == "\\":
                out.append(" ")
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
        elif in_raw:  # Go backtick raw string
            out.append("\n" if c == "\n" else " ")
            if c == "`":
                in_raw = False
            i += 1
        elif c == "`":
            in_raw = True
            out.append(" ")
            i += 1
        elif c in ('"', "'"):
            in_str = True
            quote = c
            out.append(" ")
            i += 1
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _excerpt(text: str, off: int) -> str:
    ls = text.rfind("\n", 0, off) + 1
    le = text.find("\n", off)
    if le == -1:
        le = len(text)
    return text[ls:le].strip()[:200]


def _stable_id(rel, kind, subject, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{kind}|{subject}|{line}".encode())
    return h.hexdigest()[:16]


def _paren_span(text: str, open_idx: int):
    depth = 0
    n = len(text)
    i = open_idx
    while i < n:
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i
        i += 1
    return text[open_idx + 1:], -1


def _brace_span(text: str, open_idx: int):
    depth = 0
    n = len(text)
    i = open_idx
    while i < n:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i
        i += 1
    return text[open_idx + 1:], -1


# ============================================================================
# Go function iteration: (name, receiver, params, return_sig, body, body_off).
# ============================================================================
_FUNC_RE = re.compile(
    r"\bfunc\b\s*(?:\(\s*(?P<recv>[^)]*)\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\(")


class _GoFn:
    __slots__ = ("name", "receiver", "params", "return_sig", "body",
                 "body_off", "sig")

    def __init__(self, name, receiver, params, return_sig, body, body_off, sig):
        self.name = name
        self.receiver = receiver
        self.params = params
        self.return_sig = return_sig
        self.body = body
        self.body_off = body_off
        self.sig = sig


def _iter_functions(text: str):
    for m in _FUNC_RE.finditer(text):
        popen = m.end() - 1
        params, pclose = _paren_span(text, popen)
        if pclose == -1:
            continue
        brace = text.find("{", pclose)
        if brace == -1:
            continue
        return_sig = text[pclose + 1:brace].strip()
        body, bclose = _brace_span(text, brace)
        if bclose == -1:
            continue
        sig = text[m.start():brace].strip()
        yield _GoFn(m.group("name"), (m.group("recv") or "").strip(),
                    params, return_sig, body, brace + 1, sig)


# ============================================================================
# map detection + map-range loops + append + sort + return reachability.
# ============================================================================
def _ident_is_map(scopes, ident: str) -> bool:
    """True if ``ident`` is (heuristically) a Go map in any of ``scopes`` (file
    text, fn params, fn body). Handles a dotted receiver field ``a.b.c`` by
    testing its LAST segment as a struct field decl."""
    seg = ident.split(".")[-1]
    e = re.escape(seg)
    pats = (
        rf"\b{e}\s*:?=\s*make\(\s*map\[",       # x := make(map[...]...)
        rf"\b{e}\s*:?=\s*map\[",                 # x := map[...]{...}
        rf"\b{e}\s+map\[",                       # struct field / param / var
        rf"\bvar\s+{e}\s+map\[",                 # var x map[...]
    )
    for s in scopes:
        if not s:
            continue
        for p in pats:
            if re.search(p, s):
                return True
    return False


# for <k>[, <v>] [:]= range <ident> {
_MAP_RANGE_RE = re.compile(
    r"\bfor\b\s+(?P<k>[A-Za-z_]\w*)\s*(?:,\s*(?P<v>[A-Za-z_]\w*)\s*)?:?=\s*"
    r"range\s+(?P<ident>[A-Za-z_][\w.]*)\s*\{")

# plain-identifier slice accumulator: slice = append(slice, ...)  (NOT m[k]=...)
_APPEND_RE = re.compile(
    r"(?P<dst>[A-Za-z_]\w*)\s*=\s*append\(\s*(?P<src>[A-Za-z_]\w*)\b")

_SORT_CALL_RE = re.compile(
    r"\b(?:sort\.(?:Slice|SliceStable|Strings|Sort|Stable|Ints|Float64s)|"
    r"slices\.(?:Sort|SortFunc|SortStableFunc))\s*\(")

_RETURN_RE = re.compile(r"\breturn\b")


def _sort_targets(text: str) -> set:
    """Set of identifiers passed to a dominating sort call (`sort.Strings(x)`,
    `sort.Slice(x, ...)`, `slices.Sort(x)`, `sort.Sort(T(x))` -> collects every
    bare identifier appearing inside the sort call's paren span)."""
    targets: set = set()
    for m in _SORT_CALL_RE.finditer(text):
        inner, close = _paren_span(text, m.end() - 1)
        if close == -1:
            inner = text[m.end():m.end() + 120]
        for idm in re.finditer(r"[A-Za-z_]\w*", inner):
            targets.add(idm.group(0))
    return targets


def _return_regions(body: str):
    """Yield (offset, text) of each return STATEMENT (balanced across a multi-line
    struct/composite literal `return &T{ ... }`)."""
    for m in _RETURN_RE.finditer(body):
        i = m.end()
        n = len(body)
        depth = 0
        start = i
        while i < n:
            ch = body[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == "\n" and depth <= 0:
                break
            i += 1
        yield m.start(), body[start:i]


# consensus-return context signals
_STRONG_FN_NAME = re.compile(
    r"\b(EndBlock(?:er)?|BeginBlock(?:er)?|InitGenesis|ExportGenesis|"
    r"PrepareProposal|ProcessProposal)\b")
_GENESIS_NAME = re.compile(r"\b(InitGenesis|ExportGenesis)\b")
_PROPOSAL_NAME = re.compile(r"\b(PrepareProposal|ProcessProposal)\b")
_ENDBLOCK_NAME = re.compile(r"\b(EndBlock(?:er)?|BeginBlock(?:er)?)\b")
_VALUPDATE_RE = re.compile(r"\bValidatorUpdate\b")
_ABCIEVENT_RE = re.compile(r"\b(?:abci\.Event|sdk\.Events|types\.Event\b)")
_GENESIS_TYPE_RE = re.compile(r"\bGenesisState\b")
_DENOM_HINT = re.compile(r"(?i)denom|address|addr|coin")
_STRSLICE_RET = re.compile(r"\[\]\s*string\b")
_KEEPER_RECV = re.compile(r"(?i)keeper")


def _classify_sink(fn: _GoFn, slice_line: str, return_regions_text: str):
    """-> (return_sink, severity, confirmed). severity 'high' only for a
    confirmable consensus return; 'medium' otherwise (FP-control)."""
    name = fn.name
    ret = fn.return_sig
    hay = ret + " " + slice_line + " " + return_regions_text
    # validator-update (strongest): EndBlock returning ValidatorUpdate
    if _VALUPDATE_RE.search(hay):
        return "validator-update", "high", True
    if _ABCIEVENT_RE.search(hay):
        return "abci-event", "high", True
    if _GENESIS_NAME.search(name) or _GENESIS_TYPE_RE.search(ret):
        return "genesis-export", "high", True
    if _PROPOSAL_NAME.search(name):
        return "proposal-tx-order", "high", True
    if _ENDBLOCK_NAME.search(name):
        # EndBlock/BeginBlock returning some assembled slice but not a recognised
        # abci type -> still consensus context, but sink type unconfirmed.
        return "keeper-return", "medium", False
    # a Keeper method returning []string of denoms/addresses (store-/ABCI-fed).
    if _STRSLICE_RET.search(ret) and _DENOM_HINT.search(hay):
        return "denom-slice", "medium", False
    if _KEEPER_RECV.search(fn.receiver) or _KEEPER_RECV.search(fn.params):
        return "keeper-return", "medium", False
    return None, None, False


def _order_sensitive_use(dst: str, text: str) -> bool:
    """True if ``dst`` appears in ``text`` in a way whose VALUE depends on the
    slice's ORDER - i.e. at least one occurrence not wrapped in ``len(dst)`` /
    ``cap(dst)`` (both order-invariant). ``len(x)`` returning an int leaks no
    ordering, so a return that reads only ``len(dst)`` must not fire."""
    e = re.escape(dst)
    lc = re.compile(r"\b(?:len|cap)\s*\(\s*" + e + r"\s*\)")
    spans = [(m.start(), m.end()) for m in lc.finditer(text)]
    for m in re.finditer(r"\b" + e + r"\b", text):
        if not any(s <= m.start() < en for s, en in spans):
            return True
    return False


def _scan_function(fn: _GoFn, file_text: str, rel: str, rows):
    body = fn.body
    if "range" not in body or "append(" not in body:
        return
    return_regions = list(_return_regions(body))
    if not return_regions:
        return
    ret_text = " ".join(t for _o, t in return_regions)
    sort_targets = _sort_targets(body)
    seen_slices: set = set()

    for rm in _MAP_RANGE_RE.finditer(body):
        ident = rm.group("ident")
        if not _ident_is_map((file_text, fn.params, body), ident):
            continue
        loop_brace = body.find("{", rm.end() - 1)
        if loop_brace < 0:
            continue
        loop_body, loop_close = _brace_span(body, loop_brace)
        if loop_close == -1:
            continue
        for am in _APPEND_RE.finditer(loop_body):
            dst = am.group("dst")
            if dst in seen_slices:
                continue
            # dst must be a plain slice accumulator, not the loop's key/value var.
            if dst in (rm.group("k"), rm.group("v")):
                continue
            after = body[loop_close + 1:]
            # (a) dominating-sort suppressor: the slice is sorted anywhere.
            if dst in sort_targets:
                continue
            # reaches a consensus return: directly named in a return region, OR
            # transitively ranged-over later to build the returned structure.
            # FP-control: a return that only reads `len(dst)` / `cap(dst)` is
            # ORDER-INVARIANT (length/capacity does not depend on map-iteration
            # order), so it does not leak the nondeterministic ordering - it must
            # NOT fire. Require at least one order-SENSITIVE occurrence of dst
            # (bare `dst`, `dst[i]`, `range dst`), never a len()/cap()-only read.
            direct = any(_order_sensitive_use(dst, t)
                         for _o, t in return_regions)
            indirect = bool(
                re.search(r"\brange\s+" + re.escape(dst) + r"\b", after))
            if not (direct or indirect):
                continue  # (c) never reaches a return -> local/logging only
            sink, sev, confirmed = _classify_sink(
                fn, loop_body[am.start():am.start() + 120], ret_text)
            if sink is None:
                continue
            seen_slices.add(dst)
            loop_off = fn.body_off + rm.start()
            line = _line_of_offset(file_text, loop_off)
            excerpt = _excerpt(file_text, loop_off)
            rows.append(_mk_row(
                rel, fn.name, line, ident, dst, sink, sev, excerpt,
                _why(fn, ident, dst, sink, confirmed, indirect)))


def _why(fn, map_var, slice_var, sink, confirmed, indirect):
    hop = (f"via a later `range {slice_var}` that assembles the returned "
           f"structure") if indirect else "directly in the return"
    base = (
        f"`for k := range {map_var}` iterates in Go's RANDOMIZED map order and "
        f"the loop body does `{slice_var} = append({slice_var}, ...)`; "
        f"`{slice_var}` then reaches the {sink} consensus return of "
        f"`{fn.name}` ({hop}) with NO dominating `sort.*` on `{slice_var}` "
        f"before the sink. Two honest validators therefore serialize the return "
        f"in DIFFERENT orders -> divergent AppHash -> chain halt "
        f"(consensus-safety).")
    if confirmed:
        return base + (
            f" The sink is a CONFIRMED consensus-serialized return "
            f"({sink}); severity=high. Fix: `sort.Slice/Strings({slice_var}, "
            f"...)` (or iterate a pre-sorted key slice) before the sink.")
    return base + (
        f" The sink is a Keeper return that is store-/ABCI-fed but could not be "
        f"CONFIRMED consensus-serialized from static shape alone; severity="
        f"medium pending the return-path trace. Fix: sort before the sink.")


# ============================================================================
# row builder
# ============================================================================
def _mk_row(rel, fn, line, map_var, slice_var, return_sink, severity, excerpt,
            why):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, return_sink, fn + "|" + slice_var, line),
        "file": rel,
        "line": line,
        "function": fn,
        "map_var": map_var,
        "slice_var": slice_var,
        "return_sink": return_sink,
        "sort_absent": True,
        "excerpt": excerpt,
        "severity": severity,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


# ============================================================================
# per-file scan
# ============================================================================
def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    if not rel.lower().endswith(".go"):
        return []
    text = _mask_comments(raw)
    rows = []
    for fn in _iter_functions(text):
        _scan_function(fn, text, rel, rows)
    return rows


# ============================================================================
# tree walk + sidecar
# ============================================================================
def _iter_source_files(root: Path, workspace: Path = None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not low.endswith(".go"):
                continue
            if low.endswith("_test.go") or low.endswith(".pb.go") \
                    or low.endswith(".pulsar.go"):
                continue
            if _TEST_HINT.search(f) or low.startswith("mock") \
                    or low.startswith("test"):
                continue
            p = Path(dp) / f
            rel = str(p)
            if _OFFCONSENSUS_PATH.search(rel.replace(os.sep, "/")):
                continue
            if (is_test_target_path(rel)
                    or is_chimera_mutation_harness_path(rel)
                    or is_codegen_path(rel, workspace)):
                continue
            try:
                head = p.read_text(encoding="utf-8", errors="replace")[:4096]
                if _CODEGEN_SENTINEL.search(head):
                    continue
            except OSError:
                continue
            yield p


def scan_tree(root: Path, workspace: Path = None):
    rows = []
    for p in _iter_source_files(root, workspace):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            rows.extend(scan_file(p, rel))
        except Exception:
            continue
    return rows


def _emit_sidecar(ws: Path, rows):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return out


def _count(rows, key):
    out = {}
    for r in rows:
        v = str(r.get(key, ""))
        out[v] = out.get(v, 0) + 1
    return out


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "sites": len(rows),
        "fired": len(fired),
        "by_return_sink": _count(rows, "return_sink"),
        "by_severity": _count(rows, "severity"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-D consensus-nondeterministic return-ordering screen "
                    "(Go map-range -> append -> consensus return, advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(
        _STRICT_ENV, "").strip() not in ("", "0", "false")

    if args.file:
        p = Path(args.file)
        rows = scan_file(p, p.name)
        print(json.dumps(rows, indent=2))
        return 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 0

    if not args.workspace:
        ap.error("one of --workspace / --source / --file is required")

    ws = Path(args.workspace)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / args.workspace
        if cand.exists():
            ws = cand
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines()
                    if l.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["fired"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root, workspace=ws)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
