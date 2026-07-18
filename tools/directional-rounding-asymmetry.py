#!/usr/bin/env python3
"""directional-rounding-asymmetry.py - the asymmetric rounding-direction reasoning
query (fixed-point scaling rounds AGAINST the protocol on a value leg).

LOGIC CAPABILITY (docs/LOGIC_ARSENAL_BURNDOWN.md rank 2, [CRIT x87]). A DIRECTIONAL
DATAFLOW-DIFFERENCE query over an OWNED intra-repo call-graph + per-fn body
substrate, NOT a shape/token detector: the finding is the RELATION between a
value-conversion node's rounding MODE (down/floor vs up/ceil) and the DIRECTION the
rounded quantity flows relative to the protocol (owed-OUT to the user vs taken-IN by
the protocol). A survivor is a mode that VIOLATES the protocol-favoring direction, or
a mirror pair (deposit/withdraw, mint/redeem) whose two legs round the SAME way.

CORPUS SOURCE (the mined 0-day logic class - all CRITICAL)
  A mulDiv / integer-div / round in a value path rounds AGAINST the protocol (in the
  user's favor) on one leg while the mirror leg rounds the other way, so a wei-edge
  residual compounds over a batch / repeated call -> drain. Canonical: ERC-4626
  preview/convert rounding-direction bugs, share-price truncation, mint-rounds-down /
  redeem-rounds-up inversions.

THE LOGIC TRIPLE (assumption / invariant / trust-boundary)
  ASSUMPTION: every fixed-point value conversion (a * b / c, mulDiv, shares<->assets,
    amountIn<->amountOut) is TRUSTED to round in the protocol's favor - a quantity the
    protocol OWES the user rounds DOWN (never over-pays), a quantity the protocol
    COLLECTS from the user rounds UP (never under-charges).
  INVARIANT (protocol-favoring rounding): for EVERY entrypoint-reachable value-
    conversion node V with a determinable owed-direction D(V):
      D(V) == owes-out  =>  mode(V) == down/floor
      D(V) == takes-in  =>  mode(V) == up/ceil
    and for every MIRROR PAIR (P_in, P_out) the two legs round in OPPOSITE directions
    (round-trip protection: deposit-then-withdraw can never mint value).
  TRUST-BOUNDARY: no external actor privilege is required - the residual is INTRINSIC
    to the wrong rounding mode. A benign user repeats the call / batches N times and
    the sub-wei favorable residual compounds into a protocol-draining surplus.

THE DIRECTIONAL DIFFERENCE (the finding)
  Per value-conversion node V (a rounding op inside a fn body):
    mode(V)   in {down, up, unspecified}   (classified from the op form)
    D(V)      in {owes-out, takes-in, unspecified}  (from the fn's role name)
    SURVIVOR  = { V entrypoint-reachable : (D(V)==owes-out and mode(V)==up)
                                        OR (D(V)==takes-in and mode(V)==down) }
              U { mirror pair (P_in,P_out) both legs same mode (round-trip broken) }.
  FINDING = the survivors. When D(V) or mode(V) cannot be statically confirmed the
  node is emitted advisory_only=needs_source (not dropped, not claimed) - the
  direction/mode must be confirmed against source before proof.

WHY THIS IS LOGIC, NOT A SHAPE (roadmap guard-rail axes a/b/c)
  (a) the answer is a RELATION between two per-node facts (mode vs owed-direction),
      not a boolean over one token - `mulDivRoundingUp` is only a bug on an owes-out
      leg and only correct on a takes-in leg (the SAME token flips verdict by
      direction); a regex for `mulDivRoundingUp` cannot decide either way;
  (b) owed-direction is DERIVED from the fn's protocol role (preview/convert/deposit/
      withdraw/mint/redeem/amountIn/amountOut family), grounded and workspace-neutral;
  (c) mirror-pair round-trip protection is a RELATION ACROSS TWO FUNCTIONS (the in-leg
      and out-leg round modes compared), not a property of one body - mutation-
      verifiable: flip a mulDiv-floor to mulDiv-ceil on an owes-out leg and the
      survivor APPEARS; flip it back and it DISAPPEARS.

OWNED BACKEND CONSUMED
  1. An intra-repo static CALL GRAPH + per-fn BODY index built here over the workspace
     Solidity/Rust/Go source (the same self-built reachability substrate the sibling
     reasoners stale-accrual-before-value-gate-dominance.py and coupled-state-
     completeness-graph.py use - memory anchor "Go dataflow arm under-emits on NUVA").
  2. <ws>/.auditooor/dataflow_paths.jsonl (schema dataflow_path.v1, OPTIONAL) -
     CORROBORATES value-flow: a fn whose record carries a value-move / safeTransfer /
     mint / burn sink is credited as entrypoint-reachable value flow (owned go-
     dataflow / Slither sink taxonomy), UNIONed with the entrypoint-hint filter.

OUTPUT
  <ws>/.auditooor/directional_rounding_asymmetry_obligations.jsonl - one row per
  survivor, schema `auditooor.directional_rounding_asymmetry.v1`, exploit_queue-ingest
  compatible (contract/function/file/line/source_refs/rounding_mode/owed_direction/
  root_cause_hypothesis/attack_class/broken_invariant_ids/quality_gate_status=
  'needs_source'). exploit-queue.py ingests it via
  _gather_from_directional_rounding_obligations.

  HONEST-EMPTY vs VACUOUS-EMPTY: when the repo has NO value-conversion node at all
  (no fixed-point scaling / mulDiv / preview/convert family - the class does not
  apply), the summary reports class_present=False + a cited-empty (an honest N/A),
  distinct from a vacuous empty where the source substrate (0 fns) never materialized.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# SOURCE INDEXING + intra-repo CALL GRAPH (owned reachability backend). Mirrors
# the stale-accrual / coupled-state reasoners' conventions.
# ---------------------------------------------------------------------------
_GO_DECL = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_SOL_DECL = re.compile(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_RS_DECL = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*")
_CALL = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")

_SKIP_DIR = ("/test/", "/tests/", "/mock", "/mocks/", "/vendor/",
             "/node_modules/", "/out/", "/build/", "/target/", "/.auditooor/",
             "/artifacts/", "/simulation/", "/pkg/mod/", "/go/pkg/")
_SKIP_SUFFIX = ("_test.go", ".pb.go", ".pb.gw.go", ".gen.go", ".t.sol", ".s.sol")
_STOP_NAMES = {"if", "for", "func", "return", "switch", "range", "make", "len",
               "append", "new", "cap", "require", "assert", "emit", "defer",
               "go", "select", "map", "string", "int", "uint", "error", "print",
               "printf", "sprintf", "errorf", "fmt", "panic", "recover", "var",
               "const", "type", "import", "package", "else", "while", "match"}

# ---------------------------------------------------------------------------
# ROUNDING-MODE classification (per value-conversion node = one line of a body).
# Order matters: UP tokens are checked before DOWN tokens (mulDivRoundingUp
# textually contains mulDiv; the ceil idiom (a + b - 1) / b contains a bare '/').
# ---------------------------------------------------------------------------
# Explicit UP / CEIL directives.
_ROUND_UP = re.compile(
    r"(?i)(?:"
    r"muldivroundingup|muldivup|muldivroundup|"
    r"divup|rayivup|raydivup|waddivup|mulwadup|divwadup|"
    r"ceildiv|\.ceil\b|math\.ceil|"
    r"rounding\.up|rounding\.ceil|roundup|round_up|"
    r"muldivceil"
    r")")
# Ceil IDIOM: (a + b - 1) / b  (add denominator-minus-one before dividing).
_CEIL_IDIOM = re.compile(r"\+\s*[A-Za-z_0-9.\[\]()]+\s*-\s*1\s*\)?\s*/")
# Explicit DOWN / FLOOR directives.
_ROUND_DOWN = re.compile(
    r"(?i)(?:"
    r"muldivdown|divdown|raydiv\b|waddiv\b|mulwad\b|divwad\b|"
    r"mulwaddown|divwaddown|"
    r"rounding\.down|rounding\.floor|rounddown|round_down|"
    r"math\.floor|\.floor\b|"
    r"truncateint|truncatedec|quoint\d*|quoraw|quorem|\.quo\s*\(|"
    r"muldiv\b"  # OZ 3-arg mulDiv defaults to FLOOR (checked after the *Up tokens)
    r")")
# Bare fixed-point SCALING with no explicit directive: a * b / c  -> integer div
# truncates toward zero == FLOOR (down).
_SCALE_FLOOR = re.compile(
    r"[A-Za-z_0-9.\[\]()]+\s*\*\s*[A-Za-z_0-9.\[\]()]+\s*/\s*[A-Za-z_0-9.\[\]()]+")


def classify_rounding(line: str) -> str:
    """Return 'up' / 'down' / '' for a single source line's value conversion."""
    if _ROUND_UP.search(line):
        return "up"
    if _CEIL_IDIOM.search(line):
        return "up"
    if _ROUND_DOWN.search(line):
        return "down"
    if _SCALE_FLOOR.search(line):
        return "down"
    return ""


# ---------------------------------------------------------------------------
# OWED-DIRECTION classification (per fn, from its protocol-role name). owes-out =
# the fn computes a quantity the protocol PAYS the user (must round DOWN). takes-in
# = the fn computes a quantity the protocol COLLECTS (must round UP).
# ---------------------------------------------------------------------------
_OWES_OUT = re.compile(
    r"(?i)^(?:_?"
    r"previewredeem|previewwithdraw|converttoassets|_?converttoassets|"
    r"redeem\w*|withdraw\w*|_?withdraw\w*|"
    r"maxwithdraw|maxredeem|"
    r"claim\w*|claimable\w*|pendingreward\w*|earned\w*|"
    r"getamountout|amountout\w*|quoteout\w*|getamountsout|"
    r"assetsfor\w*|redeemamount\w*|payout\w*|"
    r"tokensforshares\w*|assetstoreturn\w*"
    r")$")
_TAKES_IN = re.compile(
    r"(?i)^(?:_?"
    r"previewdeposit|previewmint|converttoshares|_?converttoshares|"
    r"deposit\w*|_?deposit\w*|mint\w*|_?mint\w*|"
    r"maxdeposit|maxmint|"
    r"repay\w*|"
    r"getamountin|amountin\w*|quotein\w*|getamountsin|"
    r"sharesfor\w*|feefor\w*|feeamount\w*|"
    r"computetransferfee|computefee\w*|\w*transferfee\w*|"
    r"sharestomint\w*|collateralrequired\w*"
    r")$")

# Mirror-pair role tags: two legs that form a round-trip. Same TAG + opposite side.
_MIRROR_TAGS = (
    ("converttoshares", "converttoassets"),
    ("previewdeposit", "previewredeem"),
    ("previewdeposit", "previewwithdraw"),
    ("previewmint", "previewwithdraw"),
    ("deposit", "withdraw"),
    ("mint", "redeem"),
    ("getamountin", "getamountout"),
)

# Entrypoint-role hint (used to RANK/permission, never to drop a survivor unless a
# confident classifier says internal - fail-open, never-false-negative).
_ENTRY_HINT = re.compile(
    r"(?i)^(?:_?"
    r"deposit\w*|mint\w*|withdraw\w*|redeem\w*|preview\w*|convert\w*|"
    r"swap\w*|borrow\w*|repay\w*|liquidate\w*|claim\w*|"
    r"getamount\w*|quote\w*|flashloan\w*|settle\w*|rebalance\w*"
    r"|computetransferfee|computefee\w*"
    r")$")


def owed_direction(name: str) -> str:
    if _OWES_OUT.match(name):
        return "owes-out"
    if _TAKES_IN.match(name):
        return "takes-in"
    return "unspecified"


def _mirror_tag(name: str) -> str:
    low = name.lower().lstrip("_")
    for a, b in _MIRROR_TAGS:
        if low.startswith(a):
            return f"{a}|{b}:in"
        if low.startswith(b):
            return f"{a}|{b}:out"
    return ""


def _lang_of(path: str) -> str:
    p = path.lower()
    if p.endswith(".go"):
        return "go"
    if p.endswith(".sol"):
        return "solidity"
    if p.endswith(".rs"):
        return "rust"
    return ""


def _iter_source_files(root: Path):
    for dp, dns, fns in os.walk(root):
        low = (dp.replace("\\", "/") + "/").lower()
        if any(s in low for s in _SKIP_DIR):
            dns[:] = []
            continue
        for f in fns:
            if not f.endswith((".go", ".sol", ".rs")):
                continue
            if any(f.endswith(s) for s in _SKIP_SUFFIX):
                continue
            yield Path(dp) / f


def _decl_re_for(lang: str):
    return {"go": _GO_DECL, "solidity": _SOL_DECL, "rust": _RS_DECL}.get(lang)


class ConvNode:
    __slots__ = ("mode", "line", "text")

    def __init__(self, mode, line, text):
        self.mode = mode
        self.line = line
        self.text = text


class Fn:
    __slots__ = ("name", "file", "line", "lang", "callees",
                 "owed", "mirror_tag", "conv_nodes")

    def __init__(self, name, file, line, lang):
        self.name = name
        self.file = file
        self.line = line
        self.lang = lang
        self.callees: set[str] = set()
        self.owed = owed_direction(name)
        self.mirror_tag = _mirror_tag(name)
        self.conv_nodes: list[ConvNode] = []


def _scan_conv_nodes(body: str, base_line: int) -> list:
    nodes = []
    for i, ln in enumerate(body.splitlines()):
        # ignore comment-only lines to avoid classifying prose "round up".
        stripped = ln.strip()
        if stripped.startswith("//") or stripped.startswith("*") or \
                stripped.startswith("#"):
            continue
        mode = classify_rounding(ln)
        if mode:
            nodes.append(ConvNode(mode, base_line + i, stripped[:200]))
    return nodes


def build_call_graph(root: Path) -> dict:
    """Fold workspace source into per-fn Fn nodes with resolved intra-repo callee
    edges + per-fn value-conversion nodes (with rounding mode). Name collisions
    UNION bodies (conservative for a reachability set query)."""
    fns: dict[str, Fn] = {}
    raw: list[tuple[str, str, int, str, str]] = []
    for fp in _iter_source_files(root):
        lang = _lang_of(str(fp))
        drx = _decl_re_for(lang)
        if not drx:
            continue
        try:
            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        cur = None
        buf: list[str] = []
        cur_line = 0
        for i, ln in enumerate(lines, 1):
            m = drx.match(ln)
            if m:
                if cur is not None:
                    raw.append((cur, str(fp), cur_line, lang, "\n".join(buf)))
                cur = m.group(1)
                cur_line = i
                buf = [ln]
            elif cur is not None:
                buf.append(ln)
        if cur is not None:
            raw.append((cur, str(fp), cur_line, lang, "\n".join(buf)))

    known = {r[0] for r in raw}
    for name, file, line, lang, body in raw:
        fn = fns.get(name)
        if fn is None:
            fn = Fn(name, file, line, lang)
            fns[name] = fn
        fn.conv_nodes.extend(_scan_conv_nodes(body, line))
        for c in _CALL.findall(body):
            if c in _STOP_NAMES:
                continue
            if c in known and c != name:
                fn.callees.add(c)
    return fns


def forward_closure(name: str, fns: dict, cap: int = 4000) -> set:
    seen = {name}
    stack = [name]
    while stack and len(seen) < cap:
        x = stack.pop()
        fx = fns.get(x)
        if not fx:
            continue
        for y in fx.callees:
            if y not in seen:
                seen.add(y)
                stack.append(y)
    return seen


# ---------------------------------------------------------------------------
# VALUE-FLOW corroboration from the owned dataflow backend (optional).
# ---------------------------------------------------------------------------
_VALUE_SINK_KINDS = {"value-move", "burn", "mint", "safeTransfer",
                     "safeTransferFrom"}


def _bare(fnid: str) -> str:
    s = (fnid or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    s = s.split("(")[0].replace("*", "")
    return s.split(".")[-1].strip()


def load_dataflow_value_fns(df_paths: list) -> set:
    value_fns: set = set()
    for df in df_paths:
        if not df.is_file():
            continue
        try:
            for line in df.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("degraded"):
                    continue
                src = rec.get("source") or {}
                sink = rec.get("sink") or {}
                fn = _bare(src.get("fn") or sink.get("fn") or "")
                if fn and str(sink.get("kind") or "") in _VALUE_SINK_KINDS:
                    value_fns.add(fn)
        except Exception:
            continue
    return value_fns


# ---------------------------------------------------------------------------
# CLASSIFY: entrypoint-reachable set; per-node directional-violation survivors +
# mirror-pair same-direction survivors.
# ---------------------------------------------------------------------------
def _entrypoint_reachable(fns: dict, value_fns: set) -> set:
    """Union of forward closures of every entry-hint fn (fail-open: if NO entry
    hint exists, keep every conv-bearing fn so we never false-negative)."""
    entries = [n for n, f in fns.items() if _ENTRY_HINT.match(n)]
    if not entries:
        return set(fns)  # fail-open
    reach: set = set()
    for e in entries:
        reach |= forward_closure(e, fns)
    reach |= value_fns  # dataflow-corroborated value flow
    reach |= set(entries)
    return reach


def classify(fns: dict, value_fns: set) -> dict:
    conv_fns = {n: f for n, f in fns.items() if f.conv_nodes}
    class_present = bool(conv_fns)
    reachable = _entrypoint_reachable(fns, value_fns)

    directional_survivors = []   # confirmed direction+mode violations
    advisory_nodes = []          # conv nodes where direction OR mode unspecified
    for name, fn in conv_fns.items():
        if name not in reachable:
            continue
        for cn in fn.conv_nodes:
            if fn.owed == "owes-out" and cn.mode == "up":
                directional_survivors.append((name, fn, cn,
                    "owes-out quantity rounds UP (over-pays the user)"))
            elif fn.owed == "takes-in" and cn.mode == "down":
                directional_survivors.append((name, fn, cn,
                    "takes-in quantity rounds DOWN (under-charges the user)"))
            elif fn.owed == "unspecified" or cn.mode == "":
                advisory_nodes.append((name, fn, cn))
            # (owes-out+down / takes-in+up = protocol-favoring, CORRECT: no survivor)

    # MIRROR-PAIR round-trip: two legs of the same pair rounding the SAME direction.
    mirror_survivors = []
    by_pair: dict = collections.defaultdict(lambda: {"in": [], "out": []})
    for name, fn in conv_fns.items():
        if name not in reachable or not fn.mirror_tag:
            continue
        pair, side = fn.mirror_tag.rsplit(":", 1)
        modes = {cn.mode for cn in fn.conv_nodes if cn.mode}
        if modes:
            by_pair[pair][side].append((name, fn, modes))
    for pair, legs in by_pair.items():
        for in_name, in_fn, in_modes in legs["in"]:
            for out_name, out_fn, out_modes in legs["out"]:
                shared = in_modes & out_modes
                # both legs share a rounding direction AND neither leg carries the
                # opposite mode -> no directional protection on the round-trip.
                if shared and not (in_modes ^ out_modes):
                    mirror_survivors.append(
                        (pair, in_name, in_fn, out_name, out_fn, sorted(shared)))

    return {
        "class_present": class_present,
        "n_conv_fns": len(conv_fns),
        "directional_survivors": directional_survivors,
        "mirror_survivors": mirror_survivors,
        "advisory_nodes": advisory_nodes,
    }


def _src_ref(fn: "Fn", line: int) -> str:
    return fn.file + (f":{line}" if line else "")


def make_directional_obligation(name, fn, cn, why, invariant_id,
                                permissionless) -> dict:
    favor = "DOWN/floor" if fn.owed == "owes-out" else "UP/ceil"
    root = (
        f"Function '{name}' computes a {fn.owed} quantity (a value the protocol "
        f"{'OWES the user' if fn.owed == 'owes-out' else 'COLLECTS from the user'}) "
        f"but its fixed-point conversion rounds {cn.mode.upper()} at {fn.file}:"
        f"{cn.line} (`{cn.text}`). Protocol-favoring rounding requires this leg to "
        f"round {favor}; rounding the other way means {why}. The sub-wei favorable "
        f"residual is INTRINSIC (no privilege needed) and COMPOUNDS over a batch / "
        f"repeated call -> protocol drain (ERC-4626 preview/convert rounding-"
        f"direction / share-price-truncation class). Directional dataflow difference "
        f"mode(V) VIOLATES D(V)."
    )
    return {
        "schema": "auditooor.directional_rounding_asymmetry.v1",
        "obligation_type": "directional-rounding-asymmetry",
        "contract": "",
        "function": name,
        "function_signature": name,
        "language": fn.lang,
        "source_refs": [_src_ref(fn, cn.line)],
        "file": fn.file,
        "line": cn.line,
        "rounding_mode": cn.mode,
        "owed_direction": fn.owed,
        "conversion_site": cn.text,
        "attack_class": "asymmetric-rounding-direction-fixed-point-scaling",
        "permissionless": bool(permissionless),
        "priority_rank": 0 if permissionless else 1,
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": False,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "DIRECTION_REAL: confirm at source that this quantity is genuinely "
            f"{fn.owed} (the protocol {'pays it out to' if fn.owed=='owes-out' else 'collects it from'} "
            "the user) - a mis-named helper that actually computes the opposite "
            "leg KILLS the lead.",
            "MODE_REAL: confirm the conversion truly rounds "
            f"{cn.mode.upper()} (an explicit Rounding arg / mulDiv variant / ceil "
            "idiom the line-scan may have mis-read against a comment or a sibling "
            "expression on the same line).",
            "RESIDUAL_IMPACT: show the wei-edge residual is NON-ZERO for a realistic "
            "input and COMPOUNDS (batch / repeated call) into a material drain - "
            "executed against the real conversion, not asserted.",
        ],
        "next_command": (
            "read the fn body; confirm owed-direction + rounding mode against "
            "source; if the leg genuinely rounds against the protocol, author the "
            "round-trip / repeated-call conservation invariant and drive an executed "
            "residual-drain PoC."
        ),
    }


def make_mirror_obligation(pair, in_name, in_fn, out_name, out_fn, shared,
                           invariant_id, permissionless) -> dict:
    root = (
        f"Mirror pair {{{in_name}, {out_name}}} (round-trip legs of '{pair}') BOTH "
        f"round {'/'.join(shared).upper()} - the round-trip protection is broken: a "
        f"deposit-then-withdraw (or mint-then-redeem) can net POSITIVE value because "
        f"neither leg rounds against the actor on its side. Both legs must round in "
        f"OPPOSITE directions (the in-leg favoring the protocol on entry, the out-leg "
        f"favoring it on exit). Directional dataflow difference across two functions "
        f"(ERC-4626 mint/redeem rounding-inversion class)."
    )
    return {
        "schema": "auditooor.directional_rounding_asymmetry.v1",
        "obligation_type": "directional-rounding-mirror-roundtrip",
        "contract": "",
        "function": in_name,
        "function_signature": f"{in_name} <-> {out_name}",
        "language": in_fn.lang,
        "source_refs": [_src_ref(in_fn, in_fn.line), _src_ref(out_fn, out_fn.line)],
        "file": in_fn.file,
        "line": in_fn.line,
        "rounding_mode": "/".join(shared),
        "owed_direction": "mirror-pair-same-direction",
        "mirror_in": in_name,
        "mirror_out": out_name,
        "attack_class": "asymmetric-rounding-direction-fixed-point-scaling",
        "permissionless": bool(permissionless),
        "priority_rank": 0 if permissionless else 1,
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": False,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "MIRROR_REAL: confirm the two functions are genuinely the in/out legs of "
            "one round-trip (not two unrelated conversions that share a name stem).",
            "SAME_DIRECTION: confirm BOTH legs round the same way with no "
            "compensating opposite-mode op elsewhere in either closure.",
            "ROUNDTRIP_GAIN: execute deposit->withdraw (mint->redeem) and show the "
            "actor nets >= starting balance for some input (a realized round-trip "
            "gain), not merely a theoretical asymmetry.",
        ],
        "next_command": (
            "read both leg bodies; if both genuinely round the same direction with "
            "no compensation, author the round-trip conservation invariant "
            "(balance_after <= balance_before) and drive an executed PoC."
        ),
    }


def make_advisory_obligation(name, fn, cn, invariant_id, permissionless) -> dict:
    reason = ("owed-direction of the quantity could not be statically confirmed"
              if fn.owed == "unspecified"
              else "rounding mode of the conversion could not be statically confirmed")
    root = (
        f"Function '{name}' contains a fixed-point value conversion at {fn.file}:"
        f"{cn.line} (`{cn.text}`) but its {reason}. It MAY round against the "
        f"protocol on a value leg (asymmetric rounding-direction class) - source "
        f"confirmation of the owed-direction AND the rounding mode is required "
        f"before a verdict."
    )
    return {
        "schema": "auditooor.directional_rounding_asymmetry.v1",
        "obligation_type": "directional-rounding-advisory",
        "contract": "",
        "function": name,
        "function_signature": name,
        "language": fn.lang,
        "source_refs": [_src_ref(fn, cn.line)],
        "file": fn.file,
        "line": cn.line,
        "rounding_mode": cn.mode or "unspecified",
        "owed_direction": fn.owed,
        "conversion_site": cn.text,
        "attack_class": "asymmetric-rounding-direction-fixed-point-scaling",
        "permissionless": bool(permissionless),
        "priority_rank": 2,
        "likely_severity": "medium",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": "needs_source",
        "learning_route": "mine-source",
        "falsification_requirements": [
            "DIRECTION_MODE: read the fn to determine BOTH the owed-direction (does "
            "the protocol pay this out or collect it) AND the exact rounding mode; "
            "only then can the favoring invariant be applied.",
        ],
        "next_command": (
            "read the fn body; determine owed-direction + rounding mode; if it "
            "resolves to an against-protocol leg, promote to a directional survivor "
            "and drive a residual-drain PoC."
        ),
    }


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="override source root (default <ws>/src, else <ws>)")
    ap.add_argument("--dataflow", default=None,
                    help="override dataflow_paths.jsonl (value-flow corroboration)")
    ap.add_argument("--invariant-id",
                    default="INV-PROTOCOL-FAVORING-ROUNDING-DIRECTION")
    ap.add_argument("--emit", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--emit-advisory", action="store_true",
                    help="also emit advisory_only=needs_source rows for conversions "
                         "whose direction/mode could not be statically confirmed")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the source substrate never materialized "
                         "(0 fns indexed) - a vacuous, not honest, empty")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if args.src_root:
        root = Path(args.src_root).expanduser().resolve()
    else:
        root = ws / "src" if (ws / "src").is_dir() else ws

    fns = build_call_graph(root)

    df_paths: list = []
    if args.dataflow:
        df_paths.append(Path(args.dataflow).expanduser())
    else:
        auto = ws / ".auditooor" / "dataflow_paths.jsonl"
        if auto.is_file():
            df_paths.append(auto)
        for sib in sorted((ws / ".auditooor").glob("dataflow_paths.*.jsonl")):
            df_paths.append(sib)
    value_fns = load_dataflow_value_fns(df_paths)

    res = classify(fns, value_fns)
    perm_default = True

    obligations = []
    seen = set()
    for name, fn, cn, why in res["directional_survivors"]:
        dk = (fn.file, cn.line, name, cn.mode)
        if dk in seen:
            continue
        seen.add(dk)
        obligations.append(make_directional_obligation(
            name, fn, cn, why, args.invariant_id, perm_default))
    for pair, in_name, in_fn, out_name, out_fn, shared in res["mirror_survivors"]:
        dk = ("mirror", in_name, out_name)
        if dk in seen:
            continue
        seen.add(dk)
        obligations.append(make_mirror_obligation(
            pair, in_name, in_fn, out_name, out_fn, shared,
            args.invariant_id, perm_default))
    if args.emit_advisory:
        for name, fn, cn in res["advisory_nodes"]:
            dk = ("adv", fn.file, cn.line, name)
            if dk in seen:
                continue
            seen.add(dk)
            obligations.append(make_advisory_obligation(
                name, fn, cn, args.invariant_id, perm_default))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "directional_rounding_asymmetry_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")
        # Capability-vacuity-telltale: the directional-rounding screen RAN over a
        # real indexed function surface (>=1 fn) and produced 0 survivors. PERSIST an
        # explicit cited-empty examined-record so the reasoner-firing gate scores
        # this FIRED_CLEAN (ran, examined, recorded 0) not silently VACUOUS.
        if not obligations and len(fns) > 0:
            fh.write(json.dumps({
                "schema": "auditooor.directional_rounding_asymmetry.examined_record.v1",
                "note": ("cited-empty: directional-rounding asymmetry screen ran over "
                         "the indexed function surface, 0 direction/mirror survivors"),
                "class_present": res["class_present"],
                "survivors": [],
                "report": {
                    "reasoner": "directional-rounding-asymmetry",
                    "totals": {"examined": len(fns),
                               "conversion_functions": res["n_conv_fns"]},
                },
            }) + "\n")

    substrate_vacuous = (len(fns) == 0)
    n_confirmed = len(res["directional_survivors"]) + len(res["mirror_survivors"])
    honest_empty = (n_confirmed == 0) and (not res["class_present"])

    summary = {
        "schema": "auditooor.directional_rounding_asymmetry.v1",
        "workspace": str(ws),
        "src_root": str(root),
        "dataflow": [str(p) for p in df_paths],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_functions_indexed": len(fns),
        "n_conversion_functions": res["n_conv_fns"],
        "class_present": res["class_present"],
        "n_directional_survivors": len(res["directional_survivors"]),
        "n_mirror_survivors": len(res["mirror_survivors"]),
        "n_advisory_nodes": len(res["advisory_nodes"]),
        "survivors": [
            {"fn": name, "file": fn.file, "line": cn.line,
             "owed_direction": fn.owed, "rounding_mode": cn.mode, "why": why,
             "site": cn.text}
            for name, fn, cn, why in res["directional_survivors"][:60]
        ],
        "mirror_survivors": [
            {"pair": pair, "in": in_name, "out": out_name,
             "shared_mode": sorted(shared)}
            for pair, in_name, in_fn, out_name, out_fn, shared
            in res["mirror_survivors"][:40]
        ],
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "substrate_vacuous": substrate_vacuous,
        "honest_empty_class_not_present": honest_empty,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[directional-rounding-asymmetry] {ws.name}: "
              f"fns={len(fns)} conv-fns={res['n_conv_fns']} "
              f"class_present={res['class_present']} "
              f"directional-survivors={len(res['directional_survivors'])} "
              f"mirror-survivors={len(res['mirror_survivors'])} "
              f"advisory={len(res['advisory_nodes'])} "
              f"-> {len(obligations)} directional-rounding obligation(s)")
        for s in summary["survivors"][:40]:
            print(f"  SURVIVOR {s['fn']}  owed={s['owed_direction']}  "
                  f"mode={s['rounding_mode']}  {s['file']}:{s['line']}  "
                  f"({s['why']})")
        for m in summary["mirror_survivors"][:40]:
            print(f"  MIRROR {m['in']}<->{m['out']}  both-round={m['shared_mode']}")
        if honest_empty:
            print("  HONEST-EMPTY: no fixed-point value conversion found in the "
                  "repo - the asymmetric rounding-direction class does NOT apply "
                  "(cited-empty, N/A).")
        if substrate_vacuous:
            print("  WARN VACUOUS: 0 functions indexed - source substrate never "
                  "materialized (NOT an honest empty).", file=sys.stderr)
        print(f"  -> {emit}")

    if args.fail_closed and substrate_vacuous:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
