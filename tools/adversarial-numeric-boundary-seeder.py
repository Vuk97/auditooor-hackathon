#!/usr/bin/env python3
"""adversarial-numeric-boundary-seeder.py - LOGIC CAPABILITY #8.

docs/LOGIC_ARSENAL_ROADMAP.md capability #8. This is a NUMERIC-DOMAIN BOUNDARY
DERIVATION over each fixed-point / tick / concentrated-liquidity math function's
signature + the guard predicates that partition its numeric domain, NOT a token
detector. Its OUTPUT is a set of EXECUTABLE fuzz seeds; its ENFORCE arm is a
SET-DIFFERENCE {math fns with a derived boundary domain} \\ {math fns already
exercised by a mutation-verified boundary seed}.

THE LOGIC TRIPLE (extracted from the corpus class it targets - fixed-point /
tick math off-by-one + extremal-range under/overflow, e.g. Uniswap-v3
getSqrtRatioAtTick MIN/MAX_TICK edges, mulDiv rounding at 0 / type(uint).max,
WAD/RAY scale over/underflow):
  ASSUMPTION      A math fn is exercised uniformly across its input range, so a
                  random fuzzer eventually hits the corners.
  INVARIANT       For every numeric parameter p of a fixed-point/tick math fn,
                  the reachable seed corpus MUST contain, and mutation-verify,
                  the EXACT boundary points that partition p's domain: the type
                  extrema {0,1,MAX,MAX-1[,MIN,MIN+1]}, each guard threshold T
                  with its off-by-one neighbours {T-1,T,T+1}, and each
                  fixed-point/tick fingerprint edge (the scale, scale+-1, the
                  mul-overflow point MAX/scale, MIN_TICK/MAX_TICK +-1).
  TRUST-BOUNDARY  Random fuzzing has probability ~0 of hitting an EXACT-equality
                  boundary in a 2^256 domain; an untested boundary is where the
                  fixed-point rounding / tick over/underflow bug lives.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  Membership is NOT "the fn name contains mul/tick/sqrt". It is:
    (a) a numeric-domain DERIVATION - each guard predicate over the parameter is
        PARSED into a comparison (op, threshold) and the threshold becomes a
        partition POINT of the numeric interval; the seed set is the union of
        those partition points +- 1 with the type-lattice extrema. The emitted
        values are the RESULT of interval reasoning, not a substring match; and
    (b) the ENFORCE answer is a SET-DIFFERENCE between two sets of functions
        (NEEDED = has a derived boundary domain, SEEDED = a mutation-verified
        boundary seed already exists in the corpus), whose finding is the
        subtraction NEEDED\\SEEDED - a relation over sets, not a boolean over one
        function's text.
  The fixed-point / tick sub-classification uses a NUMERIC predicate on the
  extracted literals ("is this constant a fixed-point scale 10^k / 2^k, or a
  tick-range edge?") - a property of the constant's VALUE, not of any token
  name; amount params that lack the fingerprint still receive the type-extremal
  tier so the capability never degenerates to a name filter.

OWNED BACKEND CONSUMED (no new engine built here)
  <ws>/.auditooor/dataflow_paths.jsonl (schema dataflow_path.v1) produced by
  tools/go-dataflow.py (go/ssa) and the Slither data_dependency arm. Per record
  we read source.var (the numeric parameter), source.fn (the signature, whose
  type tokens seed the type lattice), sink.kind (arithmetic / value / mint /
  burn - the mutation the boundary can break), and guard_nodes[].expr (the
  domain-partition predicates). Scoped sidecars dataflow_paths.*.jsonl (e.g. the
  per-package .nexus.jsonl a heavy Cosmos monorepo emits) are auto-unioned.

OUTPUT
  <ws>/.auditooor/numeric_boundary_seeds.jsonl - one row per (fn, param, seed
    value), schema auditooor.numeric_boundary_seed.v1: the EXECUTABLE seed corpus
    fed to the invariant-fuzz harness.
  <ws>/.auditooor/numeric_boundary_obligations.jsonl - one row per SURVIVOR of
    NEEDED\\SEEDED, schema auditooor.numeric_boundary_obligation.v1,
    exploit_queue-ingest compatible (exploit-queue.py
    _gather_from_numeric_boundary_obligations -> the queue ->
    per-fn-mimo-batch-gen OPEN-OBLIGATIONS block).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent


# ---------------------------------------------------------------------------
# scope OOS guard (single source of truth); degrade to a conservative default.
# (mirrors callgraph-set-difference-hunter._in_scope_file so the two pre-hunt
# producers agree on what an in-scope obligation surface is.)
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:  # pragma: no cover
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + str(rel).replace("\\", "/")).lower()
            return any(m in n for m in (
                "/test/", "/tests/", "_test.", ".t.sol", "/mock", "/vendor/",
                "/node_modules/", "/out/", "/build/", "/target/", "/.auditooor/",
            ))

_VENDOR_MARKERS = ("/pkg/mod/", "/go/pkg/", "/vendor/", "/node_modules/")
_CODEGEN_SUFFIXES = (".pb.go", ".pb.gw.go", ".gen.go", "_pb2.py")


def _in_scope_file(fpath: str, ws_root: Path, include_oos: bool) -> bool:
    if not fpath:
        return False
    low = fpath.replace("\\", "/").lower()
    if any(m in low for m in _VENDOR_MARKERS):
        return False
    if any(low.endswith(s) for s in _CODEGEN_SUFFIXES):
        return False
    try:
        rel = Path(fpath).resolve().relative_to(ws_root)
    except Exception:
        return False
    if not include_oos and is_oos(str(rel)):
        return False
    return True


def _short_fn(fn: str) -> str:
    s = (fn or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    s = s.split("(")[0].replace("*", "")
    return s.split(".")[-1].strip()


def _contract_of(fn: str) -> str:
    s = (fn or "").strip()
    if ")." in s:
        recv = s.rsplit(").", 1)[0].lstrip("(").lstrip("*")
        return recv.split(".")[-1]
    head = s.split("(")[0]
    parts = head.split(".")
    return parts[0] if len(parts) > 1 else ""


# ---------------------------------------------------------------------------
# Which entrypoint source kinds count as an attacker-supplied numeric argument.
# ---------------------------------------------------------------------------
_ENTRY_SRC_KINDS = {"param-entrypoint", "entrypoint", "param"}

# Downward / arithmetic / value-moving sinks whose result a boundary seed can
# actually break (a numeric corner that over/underflows the amount that gets
# moved, minted, burned, or written). authority/none are NOT arithmetic sinks.
_MATH_SINK_KINDS = {
    "burn", "mint", "value-move", "safeTransfer", "safeTransferFrom",
    "state-write", "arith", "arithmetic",
}

# A parameter var name that is NOT a numeric quantity (address / bytes / ctx /
# store handles / cosmos-collections receivers). Used to drop obviously-
# non-numeric candidate params. Comparison is on the lower-cased, underscore-
# stripped var so `_destinationAddress` == `destinationaddress` matches.
_NON_NUMERIC_VARS = {
    "ctx", "goctx", "store", "cdc", "key", "k", "m", "pk", "i", "addr",
    "address", "to", "from", "recipient", "sender", "owner", "spender",
    "account", "deladdr", "valaddr", "validator", "vault", "vaultaddr",
    "data", "sig", "signature", "hash", "prefixbz", "bz", "buf", "buffer",
    "s", "r", "v", "token", "asset", "proxyaddress", "destination",
    "destinationaddress", "user", "name", "namehash", "msg", "req", "request",
    "denom", "coin", "coins", "goctxt",
}

# A NUMERIC-AMOUNT lexicon: var names that denote a numeric quantity. This is a
# MEMBERSHIP filter only (the capability's LOGIC is the numeric-domain derivation
# + the NEEDED\\SEEDED set-difference, neither of which is a name match); a param
# also qualifies purely structurally when a guard COMPARES it to a threshold, so
# the lexicon is a supplement, never the sole gate.
_AMOUNT_VARS = {
    "amount", "amt", "amounts", "value", "val", "shares", "share", "fee",
    "fees", "rate", "price", "sqrtprice", "sqrtpricex96", "liquidity", "size",
    "delay", "deadline", "bips", "bps", "wad", "ray", "tick", "ticklower",
    "tickupper", "qty", "quantity", "num", "count", "balance", "supply",
    "principal", "interest", "apr", "weight", "ratio", "nominal", "tokens",
    "maxswapout", "maxswapin", "startindex", "index",
}

# Strong VALUE sinks: a name-lexicon param only qualifies when it reaches one of
# these (a mutation that actually moves/mints/burns/computes value), NOT a bare
# state-write (which floods on config setters - the exact noise the corpus-fuel
# prefilter removes). A param with a parsed guard-comparison qualifies against
# ANY sink (the comparison is the numeric evidence).
_STRONG_VALUE_SINKS = {"burn", "mint", "value-move", "safeTransfer",
                       "safeTransferFrom", "arith", "arithmetic"}


# ---------------------------------------------------------------------------
# TYPE LATTICE - infer the numeric domain of a parameter from the fn signature's
# type tokens. The extremal seed set is DERIVED from the width/signedness, not
# matched from any name.
# ---------------------------------------------------------------------------
_SOL_UINT = re.compile(r"\buint(\d+)?\b")
_SOL_INT = re.compile(r"\bint(\d+)?\b")
_GO_UINT = re.compile(r"\b(uint(8|16|32|64)?)\b")
_GO_INT = re.compile(r"\b(int(8|16|32|64)?)\b")


def infer_type_domain(fn_sig: str, lang: str) -> dict:
    """Derive (signed, bits, max, min, type_note) for the parameter's numeric
    domain from the signature type tokens. Falls back to an unsigned 256-bit
    (Solidity) / non-negative big-int (Go/cosmos sdkmath) domain, recorded
    honestly in type_note so a downstream reader knows it is a default."""
    sig = fn_sig or ""
    types = sig.split("(", 1)[1].rsplit(")", 1)[0] if "(" in sig and ")" in sig else ""
    low = types.lower()
    # Solidity explicit widths.
    m_u = _SOL_UINT.search(low)
    m_i = _SOL_INT.search(low)
    if lang.startswith("sol"):
        if m_i and (not m_u or low.index("int") < low.index("uint") if (m_u and "uint" in low) else m_i):
            bits = int(m_i.group(1) or 256)
            return _dom(True, bits, "solidity int%d signature token" % bits)
        if m_u:
            bits = int(m_u.group(1) or 256)
            return _dom(False, bits, "solidity uint%d signature token" % bits)
        return _dom(False, 256, "solidity default uint256 (no explicit width token)")
    # Go / cosmos.
    if lang == "go":
        # cosmos sdkmath.Int / sdk.Coin amounts are arbitrary-precision
        # non-negative big ints; model as a wide unsigned domain (256-bit proxy)
        # so the overflow-corner reasoning still applies.
        if "sdkmath.int" in low or "math.int" in low or ("int" in low and "big" in low):
            return _dom(True, 256, "cosmos sdkmath.Int arbitrary-precision (256-bit proxy)")
        gi = _GO_INT.search(low)
        gu = _GO_UINT.search(low)
        if gu:
            bits = int((gu.group(2) or "64"))
            return _dom(False, bits, "go %s signature token" % gu.group(1))
        if gi:
            bits = int((gi.group(2) or "64"))
            return _dom(True, bits, "go %s signature token" % gi.group(1))
        return _dom(False, 256, "go/cosmos default non-negative amount (256-bit proxy)")
    return _dom(False, 256, "default uint256 domain (unknown language)")


def _dom(signed: bool, bits: int, note: str) -> dict:
    if signed:
        mx = (1 << (bits - 1)) - 1
        mn = -(1 << (bits - 1))
    else:
        mx = (1 << bits) - 1
        mn = 0
    return {"signed": signed, "bits": bits, "max": mx, "min": mn, "type_note": note}


def type_extremal_seeds(dom: dict) -> list[dict]:
    """Extremal seeds derived from the type lattice - the corners a uniform
    fuzzer almost never hits in a 2^bits domain."""
    seeds = [
        {"value": "0", "int": 0, "origin": "type-extremal", "why": "zero / empty amount"},
        {"value": "1", "int": 1, "origin": "type-extremal", "why": "minimum non-zero"},
        {"value": str(dom["max"]), "int": dom["max"], "origin": "type-extremal",
         "why": "type max (overflow-adjacent)"},
        {"value": str(dom["max"] - 1), "int": dom["max"] - 1, "origin": "type-extremal",
         "why": "type max - 1 (off-by-one)"},
    ]
    if dom["signed"]:
        seeds.append({"value": str(dom["min"]), "int": dom["min"], "origin": "type-extremal",
                      "why": "type min (signed underflow-adjacent)"})
        seeds.append({"value": str(dom["min"] + 1), "int": dom["min"] + 1, "origin": "type-extremal",
                      "why": "type min + 1 (signed off-by-one)"})
    return seeds


# ---------------------------------------------------------------------------
# GUARD-PREDICATE -> PARTITION POINT. Parse a comparison expr that references
# the parameter var, extract (operator, threshold-expr), and emit the threshold
# with its off-by-one neighbours as boundary seeds. This is the numeric-domain
# derivation - the threshold is a partition point of the interval, not a token.
# ---------------------------------------------------------------------------
_CMP = re.compile(r"(<=|>=|==|!=|<|>)")
_INT_LIT = re.compile(r"^\s*(-?\d+)\s*$")
# a threshold that is a bare arithmetic scale literal like 1e18 / 10**18 / 2**96
_SCALE_LIT = re.compile(r"\b(1e\d+|10\s*\*\*\s*\d+|2\s*\*\*\s*\d+|0x[0-9a-fA-F]+)\b")


def _var_tokens(var: str) -> set[str]:
    v = (var or "").strip()
    toks = {v}
    toks.add(v.lstrip("_"))
    return {t for t in toks if t}


def parse_guard_boundaries(exprs: list[str], var: str) -> list[dict]:
    """For each guard expr that COMPARES the parameter var, return the threshold
    partition points {T-1, T, T+1}. Threshold may be an integer literal (compute
    neighbours) or a symbolic constant (emit symbolic +/- 1 exprs). This is
    boundary-value analysis over the parsed comparison, not a substring test."""
    out: list[dict] = []
    vtoks = _var_tokens(var)
    seen = set()
    for e in exprs:
        e = (e or "").strip()
        if not e:
            continue
        # strip a require(bool,string)(...) wrapper to the inner predicate.
        m = re.match(r"require\(bool,string\)\((.*),[^,]*\)\s*$", e)
        if m:
            e = m.group(1).strip()
        parts = _CMP.split(e)
        if len(parts) < 3:
            continue
        # walk operator positions: parts = [lhs, op, rhs, op2, ...]
        for i in range(1, len(parts), 2):
            op = parts[i].strip()
            lhs = parts[i - 1].strip()
            rhs = parts[i + 1].strip() if i + 1 < len(parts) else ""
            # which side is the parameter?
            lhs_is = any(t and t in _tok_set(lhs) for t in vtoks)
            rhs_is = any(t and t in _tok_set(rhs) for t in vtoks)
            thr = None
            if lhs_is and not rhs_is:
                thr = rhs
            elif rhs_is and not lhs_is:
                thr = lhs
            else:
                continue
            thr = thr.strip().rstrip(";)")
            if not thr:
                continue
            key = (op, thr)
            if key in seen:
                continue
            seen.add(key)
            lit = _INT_LIT.match(thr)
            if lit:
                t = int(lit.group(1))
                for dv, tag in ((t - 1, "T-1"), (t, "T"), (t + 1, "T+1")):
                    out.append({
                        "value": str(dv), "int": dv,
                        "origin": "guard-boundary",
                        "why": f"guard '{e}' partition point ({tag}, op {op})",
                    })
            else:
                # symbolic threshold - keep as an executable symbolic seed the
                # harness resolves (e.g. MAX_ROUTER_FEE, contractBalance).
                for expr, tag in ((f"({thr}) - 1", "T-1"), (thr, "T"), (f"({thr}) + 1", "T+1")):
                    out.append({
                        "value": expr, "int": None,
                        "origin": "guard-boundary-symbolic",
                        "why": f"guard '{e}' partition point ({tag}, op {op})",
                    })
    return out


def _tok_set(s: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_]\w*", s or ""))


# ---------------------------------------------------------------------------
# FIXED-POINT / TICK FINGERPRINT - a NUMERIC predicate on the constants that
# appear in the fn's guards / thresholds (value property, not token name). If a
# constant is a fixed-point scale (10^k, k>=6; or 2^k, k in {32,64,96,128,160,
# 192}) it fingerprints the fn as fixed-point and we add the scale, scale+-1,
# and the multiply-overflow point MAX/scale. Tick edges (+-887272 Uniswap-v3, or
# MIN_TICK/MAX_TICK identifiers) fingerprint a tick fn.
# ---------------------------------------------------------------------------
_FP_2K = {32, 64, 96, 128, 160, 192, 224}
_TICK_EDGES = {887272, -887272, 887271, -887271}
_TICK_IDENT = re.compile(r"\b(min_?tick|max_?tick|tick_?spacing)\b", re.I)


def _scale_value_of(tok: str):
    """Return the integer scale a literal token denotes IFF it is a fixed-point
    scale, else None. Pure value predicate."""
    t = tok.strip().lower().replace(" ", "")
    m = re.fullmatch(r"1e(\d+)", t)
    if m and int(m.group(1)) >= 6:
        return 10 ** int(m.group(1))
    m = re.fullmatch(r"10\*\*(\d+)", t)
    if m and int(m.group(1)) >= 6:
        return 10 ** int(m.group(1))
    m = re.fullmatch(r"2\*\*(\d+)", t)
    if m and int(m.group(1)) in _FP_2K:
        return 2 ** int(m.group(1))
    m = re.fullmatch(r"(-?\d+)", t)
    if m:
        v = int(m.group(1))
        # a decimal literal equal to 10^k (k>=6) or 2^k (k in set) is a scale
        for k in range(6, 40):
            if v == 10 ** k:
                return v
        for k in _FP_2K:
            if v == 2 ** k:
                return v
    return None


def fingerprint(exprs: list[str], dom: dict) -> dict:
    """Classify the math tier + emit fingerprint-boundary seeds from the numeric
    VALUE of constants in the guards. Returns (tier, extra_seeds)."""
    scales = set()
    tick = False
    for e in exprs:
        for tok in re.findall(r"\b\w+(?:\s*\*\*\s*\d+)?|1e\d+|0x[0-9a-fA-F]+", e or ""):
            sv = _scale_value_of(tok)
            if sv is not None:
                scales.add(sv)
        for numtok in re.findall(r"-?\d+", e or ""):
            if int(numtok) in _TICK_EDGES:
                tick = True
        if _TICK_IDENT.search(e or ""):
            tick = True
    seeds: list[dict] = []
    tier = "amount-extremal"
    if tick:
        tier = "tick"
        for edge in sorted(_TICK_EDGES):
            for dv, tag in ((edge - 1, "edge-1"), (edge, "edge"), (edge + 1, "edge+1")):
                seeds.append({"value": str(dv), "int": dv, "origin": "tick-boundary",
                              "why": f"tick-range edge ({tag})"})
    if scales:
        tier = "fixed-point" if tier != "tick" else "tick+fixed-point"
        for sc in sorted(scales):
            seeds.append({"value": str(sc), "int": sc, "origin": "fixed-point-scale",
                          "why": f"fixed-point scale {sc}"})
            seeds.append({"value": str(sc - 1), "int": sc - 1, "origin": "fixed-point-scale",
                          "why": f"fixed-point scale {sc} - 1 (rounding edge)"})
            ov = dom["max"] // sc
            seeds.append({"value": str(ov), "int": ov, "origin": "fixed-point-overflow",
                          "why": f"mul-overflow point MAX/{sc}"})
            seeds.append({"value": str(ov + 1), "int": ov + 1, "origin": "fixed-point-overflow",
                          "why": f"mul-overflow point MAX/{sc} + 1"})
    return {"tier": tier, "seeds": seeds}


# ---------------------------------------------------------------------------
# Backend fold: dataflow_paths.jsonl -> per (fn, param) math unit.
# ---------------------------------------------------------------------------
class MathUnit:
    __slots__ = ("fn", "param", "file", "line", "lang", "sink_kinds",
                 "guard_exprs", "n_records")

    def __init__(self, fn: str, param: str):
        self.fn = fn
        self.param = param
        self.file = ""
        self.line = 0
        self.lang = ""
        self.sink_kinds: set[str] = set()
        self.guard_exprs: list[str] = []
        self.n_records = 0


def _entrypoint_of(rec: dict) -> str:
    src = rec.get("source") or {}
    sink = rec.get("sink") or {}
    if str(src.get("kind") or "") in _ENTRY_SRC_KINDS and src.get("fn"):
        return str(src["fn"])
    if sink.get("fn"):
        return str(sink["fn"])
    return str(src.get("fn") or "")


def _fn_file(rec: dict, fn: str) -> str:
    sink = rec.get("sink") or {}
    src = rec.get("source") or {}
    if src.get("fn") == fn and src.get("file"):
        return str(src["file"])
    if sink.get("fn") == fn and sink.get("file"):
        return str(sink["file"])
    return str(src.get("file") or sink.get("file") or "")


def _fn_line(rec: dict, fn: str) -> int:
    src = rec.get("source") or {}
    sink = rec.get("sink") or {}
    if src.get("fn") == fn and src.get("line"):
        return int(src["line"])
    if sink.get("fn") == fn and sink.get("line"):
        return int(sink["line"])
    return int(src.get("line") or sink.get("line") or 0)


def build_units(dataflow_path: Path, ws_root: Path,
                include_oos: bool = False) -> tuple[dict, list[str]]:
    """Fold dataflow_paths.jsonl into per (fn, numeric-param) MathUnits. A unit
    qualifies when the source is a param entrypoint whose var is numeric (a
    numeric type token in the signature, or a non-address var reaching an
    arithmetic/value sink) - membership is a backend property, not a name."""
    units: dict[tuple, MathUnit] = {}
    warnings: list[str] = []
    n_total = n_degraded = 0
    if not dataflow_path.is_file():
        warnings.append(f"dataflow_paths absent: {dataflow_path}")
        return units, warnings
    with dataflow_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            n_total += 1
            if rec.get("degraded"):
                n_degraded += 1
                continue
            src = rec.get("source") or {}
            if str(src.get("kind") or "") not in _ENTRY_SRC_KINDS:
                continue
            fn = _entrypoint_of(rec)
            var = str(src.get("var") or "").strip()
            if not fn or not var:
                continue
            fpath = _fn_file(rec, fn)
            if not _in_scope_file(fpath, ws_root, include_oos):
                continue
            lang = str(rec.get("language") or "")
            sink = rec.get("sink") or {}
            skind = str(sink.get("kind") or "")
            # Drop obvious non-numeric candidate params up-front: address/handle
            # var names, and cosmos `collections.*` generic-storage receivers
            # (IndexedMap/Item/KeySet Set/Remove) whose `int64,uint64` tokens are
            # MAP-KEY type params, not the parameter's numeric type. FINAL
            # numeric qualification (guard-comparison OR amount-lexicon+value-
            # sink) is decided in run() once guards/sinks are fully folded.
            if var.lstrip("_").lower() in _NON_NUMERIC_VARS:
                continue
            if "collections." in fn or "collections/" in fn:
                continue
            k = (fn, var)
            u = units.get(k)
            if u is None:
                u = MathUnit(fn, var)
                u.file = fpath
                u.line = _fn_line(rec, fn)
                u.lang = lang
                units[k] = u
            u.n_records += 1
            if skind:
                u.sink_kinds.add(skind)
            for g in rec.get("guard_nodes") or []:
                e = g.get("expr")
                if e:
                    u.guard_exprs.append(str(e))
    if n_total and n_degraded == n_total:
        warnings.append(
            f"ALL {n_total} dataflow records are DEGRADED (compile-fail / "
            f"go-dataflow timeout) - the numeric-boundary domain is vacuously "
            f"empty because the slice never materialized, NOT because every math "
            f"fn is seeded. Re-run the dataflow engine scoped to the in-scope "
            f"package (see --alt-dataflow).")
    return units, warnings


def derive_seeds(u: MathUnit) -> dict:
    """Numeric-domain boundary DERIVATION for one (fn, param) unit -> the seed
    set + tier. This is the capability's reasoning core."""
    dom = infer_type_domain(u.fn, u.lang)
    exprs = u.guard_exprs
    fp = fingerprint(exprs, dom)
    seeds: list[dict] = []
    seeds.extend(type_extremal_seeds(dom))
    seeds.extend(parse_guard_boundaries(exprs, u.param))
    seeds.extend(fp["seeds"])
    # dedup by (value, origin)
    ded = {}
    for s in seeds:
        ded[(s["value"], s["origin"])] = s
    n_guard = sum(1 for s in seeds if s["origin"].startswith("guard-boundary"))
    # NUMERIC-MATH QUALIFICATION (backend-derived, not a pure name match):
    #   (A) >=1 guard PARTITION POINT parsed for this param  -> the param is
    #       compared to a numeric threshold => it is numeric (structural), OR
    #   (B) the var name is in the amount lexicon AND it reaches a STRONG value
    #       sink (mint/burn/value-move/transfer/arith) => a numeric quantity that
    #       moves value. A bare state-write config setter does NOT qualify via B.
    name_amt = u.param.lstrip("_").lower() in _AMOUNT_VARS
    strong_sink = bool(u.sink_kinds & _STRONG_VALUE_SINKS)
    qualifies = (n_guard > 0) or (name_amt and strong_sink)
    qual_reason = ("guard-partition-point" if n_guard > 0
                   else ("amount-name+value-sink" if qualifies else "not-numeric"))
    return {
        "tier": fp["tier"],
        "domain": dom,
        "seeds": list(ded.values()),
        "n_guard_boundaries": n_guard,
        "qualifies": qualifies,
        "qual_reason": qual_reason,
    }


# ---------------------------------------------------------------------------
# SEEDED set - which math units already carry a MUTATION-VERIFIED boundary seed
# in the workspace corpus. The set-difference NEEDED\\SEEDED is the finding.
# ---------------------------------------------------------------------------
def load_seeded_units(ws: Path) -> set[tuple]:
    """A math unit is SEEDED iff the verified-seed ledger records a
    mutation-verified boundary seed for it. Absent -> empty set -> every NEEDED
    unit is a survivor (the honest state before any boundary campaign runs)."""
    seeded: set[tuple] = set()
    p = ws / ".auditooor" / "numeric_boundary_seeds_verified.jsonl"
    if not p.is_file():
        return seeded
    for line in p.open(encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("mutation_verified") is True and r.get("function_signature") and r.get("param"):
            seeded.add((str(r["function_signature"]), str(r["param"])))
    return seeded


def make_obligation(u: MathUnit, d: dict, invariant_id: str) -> dict:
    short = _short_fn(u.fn)
    contract = _contract_of(u.fn)
    src_ref = u.file + (f":{u.line}" if u.line else "")
    boundary_vals = [s["value"] for s in d["seeds"]][:12]
    root = (
        f"Fixed-point/tick math fn '{u.fn}' param '{u.param}' ({d['tier']} tier, "
        f"{d['domain']['type_note']}) has a derived boundary domain of "
        f"{len(d['seeds'])} exact partition/extremal points "
        f"({', '.join(boundary_vals[:6])}...) but the fuzz corpus contains NO "
        f"mutation-verified seed exercising them. A uniform fuzzer hits an "
        f"EXACT-equality boundary in a 2^{d['domain']['bits']} domain with "
        f"probability ~0, so the fixed-point rounding / tick over-underflow "
        f"corner is UNTESTED (adversarial-numeric-boundary set-difference "
        f"NEEDED\\SEEDED)."
    )
    return {
        "schema": "auditooor.numeric_boundary_obligation.v1",
        "obligation_type": "unseeded-numeric-boundary",
        "contract": contract,
        "function": short,
        "function_signature": u.fn,
        "param": u.param,
        "language": u.lang,
        "tier": d["tier"],
        "source_refs": [src_ref] if src_ref else [],
        "file": u.file,
        "line": u.line,
        "sink_kinds": sorted(u.sink_kinds),
        "numeric_domain": d["domain"],
        "n_boundary_seeds": len(d["seeds"]),
        "boundary_seed_values": boundary_vals,
        "attack_class": ("fixed-point-tick-boundary-underflow-overflow"
                         if d["tier"] != "amount-extremal"
                         else "amount-extremal-boundary-under-overflow"),
        "likely_severity": "medium",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "SEED_EXERCISED: prove the invariant-fuzz harness for this fn drives "
            "EACH derived boundary value (0 / MAX / MAX-1 / each guard threshold "
            "+-1 / the fixed-point scale +-1 / mul-overflow point) - a corpus "
            "that only random-samples the domain does NOT satisfy this.",
            "MUTATION_VERIFIED: a mutation on the fixed-point/tick arithmetic "
            "(swap round-up/round-down, off-by-one on the tick bound, drop the "
            "scale) is KILLED by at least one boundary seed - else the seed is "
            "vacuous.",
            "IMPACT: show the boundary value produces a wrong fixed-point / tick "
            "result that breaks a value/solvency invariant (not merely a revert).",
        ],
        "next_command": (
            f"python3 tools/adversarial-numeric-boundary-seeder.py --workspace "
            f"<ws>  # then drive the emitted seeds for {short}:{u.param} through "
            f"the invariant-fuzz harness and mutation-verify"),
    }


def make_seed_rows(u: MathUnit, d: dict) -> list[dict]:
    contract = _contract_of(u.fn)
    short = _short_fn(u.fn)
    rows = []
    for s in d["seeds"]:
        rows.append({
            "schema": "auditooor.numeric_boundary_seed.v1",
            "contract": contract,
            "function": short,
            "function_signature": u.fn,
            "param": u.param,
            "tier": d["tier"],
            "language": u.lang,
            "value": s["value"],
            "int_value": s.get("int"),
            "origin": s["origin"],
            "rationale": s["why"],
            "file": u.file,
            "line": u.line,
            "mutation_verified": False,
        })
    return rows


def run(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--dataflow", default=None, help="override dataflow_paths.jsonl path")
    ap.add_argument("--alt-dataflow", default=None,
                    help="additional dataflow jsonl to UNION (scoped package run)")
    ap.add_argument("--include-oos", action="store_true")
    ap.add_argument("--invariant-id", default="INV-NUMERIC-BOUNDARY-SEED-COVERAGE")
    ap.add_argument("--emit-seeds", default=None)
    ap.add_argument("--emit-obligations", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the dataflow substrate is fully degraded")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    df = Path(args.dataflow).expanduser() if args.dataflow else \
        ws / ".auditooor" / "dataflow_paths.jsonl"

    units, warnings = build_units(df, ws, include_oos=args.include_oos)

    # union scoped sidecars (dataflow_paths.*.jsonl) + explicit --alt-dataflow.
    alt_paths: list[Path] = []
    if args.alt_dataflow:
        alt_paths.append(Path(args.alt_dataflow).expanduser())
    if not args.dataflow:
        for sib in sorted((ws / ".auditooor").glob("dataflow_paths.*.jsonl")):
            if sib.resolve() != df.resolve():
                alt_paths.append(sib)
    for alt in alt_paths:
        au, aw = build_units(alt, ws, include_oos=args.include_oos)
        warnings.extend(aw)
        for k, u2 in au.items():
            u = units.get(k)
            if u is None:
                units[k] = u2
                continue
            u.sink_kinds |= u2.sink_kinds
            u.guard_exprs.extend(u2.guard_exprs)
            u.n_records += u2.n_records
            if not u.file:
                u.file = u2.file

    seeded = load_seeded_units(ws)

    all_seed_rows: list[dict] = []
    obligations: list[dict] = []
    needed = 0
    tiers = {}
    for k, u in units.items():
        d = derive_seeds(u)
        if not d["seeds"] or not d["qualifies"]:
            continue
        needed += 1
        tiers[d["tier"]] = tiers.get(d["tier"], 0) + 1
        all_seed_rows.extend(make_seed_rows(u, d))
        if k not in seeded:  # SET-DIFFERENCE NEEDED \ SEEDED
            obligations.append(make_obligation(u, d, args.invariant_id))

    emit_seeds = Path(args.emit_seeds).expanduser() if args.emit_seeds else \
        ws / ".auditooor" / "numeric_boundary_seeds.jsonl"
    emit_ob = Path(args.emit_obligations).expanduser() if args.emit_obligations else \
        ws / ".auditooor" / "numeric_boundary_obligations.jsonl"
    emit_seeds.parent.mkdir(parents=True, exist_ok=True)
    with emit_seeds.open("w", encoding="utf-8") as fh:
        for r in all_seed_rows:
            fh.write(json.dumps(r) + "\n")
    with emit_ob.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    substrate_degraded = any("DEGRADED" in w for w in warnings) and not units

    summary = {
        "schema": "auditooor.numeric_boundary_seeder.v1",
        "workspace": str(ws),
        "dataflow": str(df),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_math_units": len(units),
        "size_NEEDED": needed,
        "size_SEEDED": len(seeded),
        "size_DIFF_survivors": len(obligations),
        "tiers": tiers,
        "seeds_written": len(all_seed_rows),
        "seeds_path": str(emit_seeds),
        "obligations_written": len(obligations),
        "obligations_path": str(emit_ob),
        "survivors": [
            {"fn": _short_fn(o["function_signature"]), "param": o["param"],
             "tier": o["tier"], "n_boundary_seeds": o["n_boundary_seeds"],
             "file": o["file"], "line": o["line"]}
            for o in obligations
        ][:60],
        "warnings": warnings,
        "substrate_degraded": substrate_degraded,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[numeric-boundary-seeder] {ws.name}: "
              f"math-units={len(units)} NEEDED={needed} SEEDED={len(seeded)} "
              f"survivors(NEEDED\\SEEDED)={len(obligations)} "
              f"-> {len(all_seed_rows)} boundary seed(s), "
              f"{len(obligations)} unseeded-boundary obligation(s)")
        print(f"  tiers: {tiers}")
        for s in summary["survivors"][:40]:
            print(f"  SURVIVOR {s['fn']}:{s['param']}  [{s['tier']}]  "
                  f"{s['n_boundary_seeds']} seeds  {s['file']}:{s['line']}")
        for w in warnings:
            print(f"  WARN {w}", file=sys.stderr)
        print(f"  -> seeds {emit_seeds}")
        print(f"  -> obligations {emit_ob}")

    if args.fail_closed and substrate_degraded:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
