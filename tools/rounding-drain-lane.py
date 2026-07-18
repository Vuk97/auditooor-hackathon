#!/usr/bin/env python3
"""rounding-drain-lane.py  (RDL) - Rounding-Drain Lane.

WHAT THIS TOOL DOES
===================
For every value-moving function in <ws>/.auditooor/value_moving_functions.json,
RDL scans the function body for rounding operations (mulDivDown / mulDivUp /
FullMath.mulDiv / x*y/z / Go sdk.Dec.Quo / Rust integer div / .floor() / .ceil()
etc.) then classifies the rounding DIRECTION relative to protocol safety.

DIRECTION CLASSIFIER
====================
The rounding site is classified by what the rounded quantity represents:

  PROTOCOL-PAYOUT path (value-OUT): the protocol sends tokens to a user, mints
  shares/LP/units for a user, or reduces a user's debt.
    Safe direction = round DOWN (user gets floor). -> skip (SAFE).
    Drainable direction = round UP (user gets more than exact). -> flag.

  PROTOCOL-INTAKE path (value-IN): a user pays tokens to the protocol, or the
  protocol accrues a fee/debt obligation.
    Safe direction = round UP (protocol collects ceil). -> skip (SAFE).
    Drainable direction = round DOWN (protocol collects floor). -> flag.

  AMBIGUOUS: the flow cannot be traced to a terminal transfer without
  inter-procedural analysis. -> flag (needs-fuzz).

WHY VCIS MISSES THIS
====================
The VCIS solvency-floor invariant (balanceOf >= sum(liabilities)) is written with
>= slack and TOLERATES per-operation 1-wei rounding errors. A 1-wei drain per call
satisfies the solvency-floor but compounds over millions of operations into a real
drain. VCIS structurally misses this class; RDL is the dedicated lane.

NO-FLOOD RULE
=============
Almost every value-mover has a mulDiv. RDL flags ONLY when ALL three gates pass:

  GATE-A (value path): the rounding op is inside a value-moving function
    (sourced from value_moving_functions.json).
  GATE-B (direction): the rounding direction is user-favoring (payout path +
    mulDivUp / intake path + mulDivDown) OR statically AMBIGUOUS.
  GATE-C (context): the rounded value flows to a payout / mint / fee-accrual /
    credit path (inferred from naming and structural tokens near the call site).
    A clearly protocol-favoring round (payout + mulDivDown) scores 0.

DO NOT FLAG: every mulDiv is NOT flagged. A clearly protocol-favoring round
(e.g. amount the protocol RECEIVES rounded DOWN when that is safe, or amount the
USER PAYS rounded UP) produces 0 hypotheses.

NO FALSE-GREEN RULE
===================
RDL NEVER auto-credits a confirmed finding. Every emitted record carries
verdict="needs-fuzz". An exact/monotone conservation invariant spec is emitted
as the fuzzer oracle hint.

LANGUAGES SUPPORTED
===================
- Solidity: mulDivDown / mulDivUp / FullMath.mulDiv / mulDiv / x*y/z (div inline)
- Go/Cosmos: sdk.Dec.Quo / QuoInt / TruncateInt / RoundInt / Ceil / new(big.Int).Div
- Rust: checked_div / wrapping_div / saturating_div / integer / .floor() / .ceil()
  / FPDecimal rounding / u128::from / u64::from (integer coercion after multiply)

OUTPUT FILES
============
1. <ws>/.auditooor/rounding_drain_hypotheses.jsonl  - hypothesis records
2. <ws>/.auditooor/rounding_drain_invariants.jsonl  - invariant specs

HYPOTHESIS SCHEMA
=================
{
  "workspace":         "<abs-path>",
  "file":              "<rel-path>",
  "function":          "<fn-name>",
  "language":          "sol|go|rs",
  "rounding_op":       "<matched snippet>",
  "rounding_site":     "<rel-path>:<approx-line>",
  "direction":         "DRAINABLE|AMBIGUOUS",
  "direction_reason":  "<why>",
  "value_path":        "payout|intake|ambiguous",
  "conservation_invariant": "<exact/monotone invariant text>",
  "attack_class":      "rounding-drain",
  "source":            "RDL",
  "verdict":           "needs-fuzz"
}

CLI
===
  python3 tools/rounding-drain-lane.py <workspace> [--out <path>] [--out-inv <path>]
  --vmf-json:   override value_moving_functions.json path
  --regen-vmf:  re-run value-moving-functions.py even if JSON exists

Returns rc=0 on success (even if 0 hypotheses emitted), rc=1 on error.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Compose with scope_exclusion (single source of truth OOS guard).
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:
    _HERE = Path(__file__).resolve().parent
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + rel.replace("\\", "/")).lower()
            for marker in (
                "/test/", "/tests/", "_test.", ".t.sol", "/vendor/", "/lib/",
                "/node_modules/", "/out/", "/build/", "/target/",
            ):
                if marker in n:
                    return True
            return False

# ---------------------------------------------------------------------------
# Lazy-load value-moving-functions module.
# ---------------------------------------------------------------------------
_VMF_MOD_NAME = "value_moving_functions_rdl_import"
_VMF_PATH = Path(__file__).resolve().parent / "value-moving-functions.py"


def _load_vmf_module():
    spec = importlib.util.spec_from_file_location(_VMF_MOD_NAME, _VMF_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_VMF_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


_VMF: Any = None


def _vmf() -> Any:
    global _VMF
    if _VMF is None:
        _VMF = _load_vmf_module()
    return _VMF


# ---------------------------------------------------------------------------
# ROUNDING OPERATION PATTERNS (per language).
#
# Each entry: (op_label, pattern, default_direction_hint)
#   default_direction_hint: "down" | "up" | "ambiguous"
#     "down" = result truncated toward zero (floor division)
#     "up"   = result rounded away from zero (ceiling division)
#     "ambiguous" = direction depends on context or runtime state
# ---------------------------------------------------------------------------

_SOL_ROUNDING: list[tuple[str, re.Pattern, str]] = [
    # mulDivDown(a, b, d) -> floor(a*b/d) -> rounds DOWN
    ("mulDivDown", re.compile(r"\bmulDivDown\s*\(", re.I), "down"),
    # mulDivUp(a, b, d) -> ceil(a*b/d) -> rounds UP
    ("mulDivUp",   re.compile(r"\bmulDivUp\s*\(", re.I), "up"),
    # FullMath.mulDiv / PRBMath.mulDiv - rounds DOWN by default
    ("FullMath.mulDiv", re.compile(r"\bFullMath\s*\.\s*mulDiv\s*\(", re.I), "down"),
    ("mulDiv",     re.compile(r"\bmulDiv\s*\(", re.I), "down"),
    # Inline integer division x * y / z or x / y (ambiguous without context)
    ("x*y/z",      re.compile(r"\b\w+\s*\*\s*\w+\s*/\s*\w+"), "ambiguous"),
    # roundUp flag or roundUpDiv pattern
    ("roundUpDiv", re.compile(r"\broundUp(?:Div)?\s*\(", re.I), "up"),
    ("roundDown",  re.compile(r"\broundDown\s*\(", re.I), "down"),
    # divCeil / ceilDiv
    ("divCeil",    re.compile(r"\b(?:divCeil|ceilDiv)\s*\(", re.I), "up"),
]

_GO_ROUNDING: list[tuple[str, re.Pattern, str]] = [
    # sdk.Dec.Quo -> truncates (floor for positive) -> down
    ("sdk.Dec.Quo",      re.compile(r"\b\.Quo\s*\("), "down"),
    # QuoInt -> integer quotient, truncates -> down
    ("QuoInt",           re.compile(r"\b\.QuoInt\s*\("), "down"),
    # TruncateInt -> floor -> down
    ("TruncateInt",      re.compile(r"\b\.TruncateInt\s*\("), "down"),
    # RoundInt -> rounds to nearest (ambiguous - could go either way)
    ("RoundInt",         re.compile(r"\b\.RoundInt\s*\("), "ambiguous"),
    # Ceil -> ceiling -> up
    ("Ceil",             re.compile(r"\b\.Ceil\s*\("), "up"),
    # QuoRoundUp / QuoCeil / similar
    ("QuoRoundUp",       re.compile(r"\b\.QuoRound[Uu]p\s*\("), "up"),
    # big.Int.Div -> truncates (floor for positive) -> down
    ("big.Int.Div",      re.compile(r"\bnew\s*\(\s*big\.Int\s*\)\s*\.Div\s*\("), "down"),
    # sdk.NewDecFromInt division patterns
    ("NewDecFromInt.Div", re.compile(r"NewDecFromInt\b.*?\.Quo\s*\("), "down"),
    # NOTE: generic int_div (a / b) is intentionally omitted for Go.
    # The pattern \b[a-zA-Z_]\w*\s*/\s*[a-zA-Z_]\w*\b matches arbitrary
    # word/word text in comments (ETH/USDT, x/gov, path/to/, nil/zero, etc.)
    # and causes severe flooding.  All genuine Go rounding in value paths goes
    # through named sdk.Dec methods above (Quo/QuoInt/TruncateInt/Ceil/etc.).
]

_RS_ROUNDING: list[tuple[str, re.Pattern, str]] = [
    # checked_div -> floor division -> down
    ("checked_div",      re.compile(r"\b\.checked_div\s*\("), "down"),
    # wrapping_div -> floor division -> down
    ("wrapping_div",     re.compile(r"\b\.wrapping_div\s*\("), "down"),
    # saturating_div -> floor division -> down
    ("saturating_div",   re.compile(r"\b\.saturating_div\s*\("), "down"),
    # NOTE: generic int_div (a / b) is intentionally omitted for Rust.
    # The pattern \b\w+\s*/\s*\w+ matches arbitrary word/word in comments
    # and URL-like text, causing the same flooding seen in Go.  Real Rust
    # integer division in value paths is caught by checked_div/wrapping_div/
    # saturating_div above; FPDecimal division is caught by FPDecimal.div below.
    # .floor() on a Decimal/FPDecimal type
    ("floor",            re.compile(r"\b\.floor\s*\(\s*\)"), "down"),
    # .ceil() on a Decimal/FPDecimal type
    ("ceil",             re.compile(r"\b\.ceil\s*\(\s*\)"), "up"),
    # FPDecimal division / Decimal::from integer coercion after multiply
    ("FPDecimal.div",    re.compile(r"\bFPDecimal\b.*?/"), "ambiguous"),
    # u128::from / u64::from after a multiply (coercion may truncate)
    ("u128_coerce",      re.compile(r"\bu(?:128|64)\s*::from\s*\("), "ambiguous"),
    # mul_div helpers
    ("mul_div",          re.compile(r"\bmul_div\s*\(", re.I), "down"),
]

_ROUNDING_RES: dict[str, list[tuple[str, re.Pattern, str]]] = {
    "sol":   _SOL_ROUNDING,
    "go":    _GO_ROUNDING,
    "rs":    _RS_ROUNDING,
}

# ---------------------------------------------------------------------------
# VALUE-PATH CONTEXT SIGNALS.
#
# Applied to the local snippet (<=5 lines) around the rounding call site to
# infer whether the rounded quantity is on a PAYOUT path (value flows TO user)
# or INTAKE path (value flows FROM user TO protocol).
#
# A signal is "nearby" when it appears in the same line or within 3 lines.
# ---------------------------------------------------------------------------

# Payout context: the result of the rounding flows OUT to a user.
_PAYOUT_SIGNALS: list[re.Pattern] = [
    re.compile(r"\bsafeTransfer\b", re.I),
    re.compile(r"\btransfer\s*\(", re.I),
    re.compile(r"\bsafeTransferFrom\b", re.I),
    re.compile(r"\b_mint\s*\(", re.I),
    re.compile(r"\bmint\s*\(", re.I),
    re.compile(r"\bcredit\b", re.I),
    re.compile(r"\bunits\b", re.I),
    re.compile(r"\bshares?\b", re.I),
    re.compile(r"\bbuyerAssets\b", re.I),
    re.compile(r"\bpayout\b", re.I),
    re.compile(r"\bwithdrawAmount\b", re.I),
    re.compile(r"\bpendingFeeDecrease\b", re.I),
    re.compile(r"\bfeeDecrease\b", re.I),
    re.compile(r"\breturn\b.*amount", re.I),
    re.compile(r"\bsend\s*\(", re.I),
    re.compile(r"\bMintCoins\s*\(", re.I),
    re.compile(r"\bBankMsg\s*::\s*Send\b"),
    # Rust / CosmWasm: funds: coins(amount, ...)
    re.compile(r"\bfunds\s*:\s*(?:vec|coins)"),
]

# Intake context: the result of the rounding represents what the protocol TAKES IN.
_INTAKE_SIGNALS: list[re.Pattern] = [
    re.compile(r"\bsafeTransferFrom\b", re.I),
    re.compile(r"\btransferFrom\b", re.I),
    re.compile(r"\bfee\b", re.I),
    re.compile(r"\bFee\b"),
    re.compile(r"\bdebt\b", re.I),
    re.compile(r"\bliabilit", re.I),
    re.compile(r"\bpendingFee\b"),
    re.compile(r"\bprotocol\w*Fee\b", re.I),
    re.compile(r"\bcontinuousFee\b", re.I),
    re.compile(r"\bfeeIncrease\b", re.I),
    re.compile(r"\binterest\b", re.I),
    re.compile(r"\bborrowRate\b", re.I),
    re.compile(r"\bdeposit(?:Amount)?\b", re.I),
    re.compile(r"\bprincipal\b", re.I),
    re.compile(r"\bcollateral\b", re.I),
    re.compile(r"\bcreditIncrease\b", re.I),  # intake increase
]


def _classify_value_path(snippet: str) -> str:
    """Return 'payout', 'intake', or 'ambiguous' from a local code snippet."""
    payout_hits = sum(1 for rx in _PAYOUT_SIGNALS if rx.search(snippet))
    intake_hits = sum(1 for rx in _INTAKE_SIGNALS if rx.search(snippet))
    if payout_hits > intake_hits:
        return "payout"
    if intake_hits > payout_hits:
        return "intake"
    return "ambiguous"


# ---------------------------------------------------------------------------
# SAFE-DIRECTION lookup.
#
# Given a (rounding_direction, value_path) pair, return True when the rounding
# is SAFE (protocol-favoring), False when DRAINABLE.
#
# Convention:
#   payout + down  = SAFE (user gets floor = protocol underpays less)
#   payout + up    = DRAINABLE (user gets ceiling = protocol overpays)
#   intake + up    = SAFE (protocol collects ceiling)
#   intake + down  = DRAINABLE (protocol collects floor = under-collects)
#   ambiguous path = always emit (AMBIGUOUS direction)
# ---------------------------------------------------------------------------

def _is_safe(direction: str, value_path: str) -> bool:
    """Return True iff the rounding is unambiguously protocol-favoring."""
    if value_path == "ambiguous":
        return False  # cannot determine statically -> flag
    if direction == "ambiguous":
        return False  # cannot determine statically -> flag
    if value_path == "payout":
        return direction == "down"  # down on payout = SAFE
    if value_path == "intake":
        return direction == "up"    # up on intake = SAFE
    return False


# ---------------------------------------------------------------------------
# Context snippet extractor.
#
# Extract a window of +/- 5 source lines around the rounding match start
# to give the value-path classifier enough surrounding context.
# ---------------------------------------------------------------------------

def _context_snippet(source: str, match_start: int, window_lines: int = 5) -> str:
    """Return up to window_lines lines before + after match_start."""
    before = source[:match_start]
    after = source[match_start:]
    pre_lines = before.split("\n")[-window_lines:]
    post_lines = after.split("\n")[:window_lines]
    return "\n".join(pre_lines + post_lines)


def _approx_line(source: str, pos: int) -> int:
    return source[:pos].count("\n") + 1


# ---------------------------------------------------------------------------
# Core detection for a single function body.
#
# Returns a list of RdlHit named-tuples-ish dicts:
#   {"op_label", "snippet", "direction", "value_path"}
# Only DRAINABLE or AMBIGUOUS hits are returned (SAFE hits are dropped).
# ---------------------------------------------------------------------------

def _detect_rounding_ops(body: str, lang: str, full_source: str, body_start_pos: int) -> list[dict]:
    """Scan body for rounding ops; return only DRAINABLE/AMBIGUOUS hits.

    Uses finditer() over every match of each op pattern so that when a single
    source line contains multiple rounding ops (e.g. one SAFE + one DRAINABLE),
    each match is classified independently.  The old search()-first-match design
    missed the DRAINABLE op whenever the SAFE match occurred earlier in the body.

    Dedup policy: at most one DRAINABLE/AMBIGUOUS hit per (op_label, source_line).
    This suppresses loop-body repetition (the same pattern on the same line is not
    re-emitted) while preserving distinct occurrences on different lines.
    """
    hits: list[dict] = []
    ops = _ROUNDING_RES.get(lang, [])

    # seen_key = (op_label, approx_line_number) - prevents flooding when the
    # same op appears identically on the same line more than once.
    seen_keys: set[tuple[str, int]] = set()

    # Pre-split the body into lines for cheap comment-line suppression.
    # We use body-relative line offsets here (not full_source positions) because
    # body_start_pos = fn_match.end() points at the start of the parameter list,
    # NOT at the opening brace, so abs_pos = body_start_pos + m.start() does NOT
    # reliably map back to the correct source line via full_source.splitlines().
    # Using body-relative lines avoids that offset mismatch entirely.
    _body_lines = body.splitlines()

    def _body_line_at_offset(offset: int) -> str:
        """Return the body source-line that contains body[offset]."""
        ln = body[:offset].count("\n")
        return _body_lines[ln] if ln < len(_body_lines) else ""

    for op_label, pattern, dir_hint in ops:
        for m in pattern.finditer(body):
            # Position in full source (for line-number computation).
            abs_pos = body_start_pos + m.start()
            approx_line = _approx_line(full_source, abs_pos)

            # Skip matches that fall on a comment-only or documentation line.
            # This suppresses false positives from patterns that match arbitrary
            # word/word text in comments (e.g. ETH/USDT, x/gov, path/to/...).
            raw_line = _body_line_at_offset(m.start()).lstrip()
            if (
                raw_line.startswith("//")
                or raw_line.startswith("*")
                or raw_line.startswith("#")
                or raw_line.startswith("///")
            ):
                continue

            dedup_key = (op_label, approx_line)
            if dedup_key in seen_keys:
                continue

            ctx_snippet = _context_snippet(full_source, abs_pos, window_lines=5)
            value_path = _classify_value_path(ctx_snippet)

            direction = dir_hint
            if _is_safe(direction, value_path):
                # Provably SAFE - skip, but do NOT add to seen_keys so that a
                # second occurrence of the same op on a different line with a
                # different (drainable) context can still be flagged.
                continue

            seen_keys.add(dedup_key)
            # Capture the matching snippet (stripped, no newlines).
            raw_match = body[m.start(): min(m.end() + 40, len(body))]
            snippet = raw_match.strip().replace("\n", " ")[:100]
            hits.append({
                "op_label":   op_label,
                "snippet":    snippet,
                "direction":  direction,
                "value_path": value_path,
                "abs_pos":    abs_pos,
            })

    return hits


# ---------------------------------------------------------------------------
# Conservation invariant text builder.
# ---------------------------------------------------------------------------

_CONSERVATION_INVARIANT_TEMPLATE = (
    "ROUNDING-DRAIN conservation invariant for {fn} ({file}):\n"
    "  Exact/monotone form: for any sequence of N calls to {fn} with identical\n"
    "  inputs summing to total_in, the protocol's net intake (fees accrued +\n"
    "  token received) must satisfy:\n"
    "    protocol_net_intake(N calls) >= expected_net_intake - N\n"
    "  where expected_net_intake is computed from the exact arithmetic (no rounding).\n"
    "  Equivalently: per-call rounding error must be <= 1 wei (1 base unit) and\n"
    "  must NOT systematically favor the user over the protocol across all calls.\n"
    "  Rounding op flagged: {op_label} ({direction}) on {value_path} path.\n"
    "  NOTE: the VCIS solvency-floor (balanceOf >= liabilities) tolerates 1-wei\n"
    "  per-call drift and is INSUFFICIENT to catch this class; this invariant\n"
    "  requires a cumulative-drain oracle over repeated calls."
)

_FUZZ_PROPERTY_TEMPLATE = (
    "// Medusa/echidna property for {fn} rounding-drain check\n"
    "// Pre-state: record protocolBalanceBefore, userBalanceBefore\n"
    "// Action: call {fn}(inputs) N times in a loop\n"
    "// Post-state: verify protocolBalance >= protocolBalanceBefore + N * expected_per_call_intake - N\n"
    "// (allowing at most 1 wei rounding loss per call to the protocol)\n"
    "property roundingDrainBound_{fn_safe}() {{"
    "    // insert loop harness and cumulative assertion here\n"
    "}}"
)


def _build_hypothesis(
    ws_abs: str,
    fn_rec: dict,
    hit: dict,
    file_rel: str,
) -> dict:
    fn = fn_rec["function"]
    direction_label = hit["direction"].upper()  # "DOWN", "UP", or "AMBIGUOUS"
    vp = hit["value_path"]
    op = hit["op_label"]

    if direction_label == "DOWN" and vp == "intake":
        reason = (
            f"{op} rounds DOWN on an intake/fee path - "
            "the protocol collects floor(exact) instead of ceil(exact); "
            "repeated calls drain 1 wei per op from protocol intake."
        )
    elif direction_label == "UP" and vp == "payout":
        reason = (
            f"{op} rounds UP on a payout/mint path - "
            "the user receives ceil(exact) instead of floor(exact); "
            "repeated calls extract 1 wei per op from the protocol."
        )
    else:
        reason = (
            f"{op} (direction={direction_label}, path={vp}) - "
            "direction or value-path cannot be determined statically; "
            "may drain the protocol on repeated calls."
        )

    conservation_inv = _CONSERVATION_INVARIANT_TEMPLATE.format(
        fn=fn,
        file=file_rel,
        op_label=op,
        direction=direction_label,
        value_path=vp,
    )

    return {
        "workspace":              ws_abs,
        "file":                   file_rel,
        "function":               fn,
        "language":               fn_rec["language"],
        "rounding_op":            hit["snippet"],
        "rounding_site":          f"{file_rel}:~{hit.get('abs_line', '?')}",
        "direction":              direction_label if direction_label != "AMBIGUOUS" else "AMBIGUOUS",
        "direction_reason":       reason,
        "value_path":             vp,
        "conservation_invariant": conservation_inv,
        "vcis_miss_reason": (
            "VCIS solvency-floor uses >= slack and tolerates per-op 1-wei rounding; "
            "cumulative drain across N calls is structurally invisible to it."
        ),
        "attack_class":           "rounding-drain",
        "source":                 "RDL",
        "verdict":                "needs-fuzz",
    }


def _build_invariant_spec(
    ws_abs: str,
    fn_rec: dict,
    inv_id: str,
    hit: dict,
    file_rel: str,
) -> dict:
    fn = fn_rec["function"]
    fn_safe = re.sub(r"[^A-Za-z0-9_]", "_", fn)
    return {
        "workspace":       ws_abs,
        "file":            file_rel,
        "function":        fn,
        "language":        fn_rec["language"],
        "invariant_id":    inv_id,
        "invariant_class": "rounding-drain-conservation",
        "invariant_text":  _CONSERVATION_INVARIANT_TEMPLATE.format(
            fn=fn,
            file=file_rel,
            op_label=hit["op_label"],
            direction=hit["direction"].upper(),
            value_path=hit["value_path"],
        ),
        "fuzz_property":   _FUZZ_PROPERTY_TEMPLATE.format(fn=fn, fn_safe=fn_safe),
        "rounding_op":     hit["op_label"],
        "source":          "RDL",
        "verdict":         "needs-fuzz",
    }


# ---------------------------------------------------------------------------
# Per-function public API (used by tests without a workspace).
# ---------------------------------------------------------------------------

def hypotheses_from_source(
    source: str,
    language: str,
    fn_name: str,
    file_rel: str = "fixture.sol",
    ws_abs: str = "/tmp/rdl_fixture_ws",
) -> tuple[list[dict], list[dict]]:
    """Return (hypotheses, invariant_specs) for a single function body in source.

    Convenience wrapper for unit tests: no workspace directory required.
    source must contain the full function definition (signature + body).
    Returns a tuple of (hypotheses, invariants); both are empty if the function
    is not found, has no body, or all rounding ops are SAFE.
    """
    vmf = _vmf()
    fn_re = vmf._FN_RES.get(language)
    if fn_re is None:
        return [], []

    fn_match = None
    for m in fn_re.finditer(source):
        if m.group(1) == fn_name:
            fn_match = m
            break
    if fn_match is None:
        return [], []

    body_start = fn_match.end()
    body = vmf._extract_body(source, body_start)
    if not body:
        return [], []

    hits = _detect_rounding_ops(body, language, source, body_start)
    if not hits:
        return [], []

    fn_rec = {
        "file":     file_rel,
        "function": fn_name,
        "language": language,
    }

    hypotheses: list[dict] = []
    invariants: list[dict] = []
    for i, hit in enumerate(hits, start=1):
        hit["abs_line"] = _approx_line(source, hit["abs_pos"])
        hyp = _build_hypothesis(ws_abs, fn_rec, hit, file_rel)
        inv = _build_invariant_spec(ws_abs, fn_rec, f"RDL-{i}", hit, file_rel)
        hypotheses.append(hyp)
        invariants.append(inv)

    return hypotheses, invariants


# ---------------------------------------------------------------------------
# Workspace-level runner.
# ---------------------------------------------------------------------------

def run_rdl(
    workspace: str | Path,
    vmf_json_path: str | Path | None = None,
    out_path: str | Path | None = None,
    out_inv_path: str | Path | None = None,
    regen_vmf: bool = False,
) -> tuple[list[dict], list[dict]]:
    """Run RDL over workspace and return (hypotheses, invariants).

    Also writes the .jsonl sidecars.
    """
    ws = Path(workspace).resolve()
    ws_abs = str(ws)

    vmf_json = (
        Path(vmf_json_path)
        if vmf_json_path is not None
        else ws / ".auditooor" / "value_moving_functions.json"
    )

    if regen_vmf or not vmf_json.exists():
        vmf_mod = _vmf()
        out_vmf = vmf_mod.run(ws, vmf_json)
        vmf_json = out_vmf

    if not vmf_json.exists():
        print(
            f"ERROR: value_moving_functions.json not found at {vmf_json}",
            file=sys.stderr,
        )
        return [], []

    payload = json.loads(vmf_json.read_text(encoding="utf-8"))
    fn_records: list[dict] = payload.get("functions", [])

    by_file: dict[str, list[dict]] = {}
    for rec in fn_records:
        by_file.setdefault(rec["file"], []).append(rec)

    all_hypotheses: list[dict] = []
    all_invariants: list[dict] = []
    inv_counter = 0

    for rel_path, recs in by_file.items():
        abs_path = ws / rel_path
        if not abs_path.exists():
            continue
        if is_oos(rel_path):
            continue
        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        fn_re = _vmf()._FN_RES.get(recs[0]["language"])
        if fn_re is None:
            continue

        match_by_name: dict[str, re.Match] = {}
        for m in fn_re.finditer(source):
            name = m.group(1)
            if name not in match_by_name:
                match_by_name[name] = m

        for fn_rec in recs:
            fn_name = fn_rec["function"]
            lang = fn_rec["language"]
            fn_match = match_by_name.get(fn_name)
            if fn_match is None:
                continue

            body_start = fn_match.end()
            body = _vmf()._extract_body(source, body_start)
            if not body:
                continue

            hits = _detect_rounding_ops(body, lang, source, body_start)
            if not hits:
                continue

            for hit in hits:
                inv_counter += 1
                inv_id = f"RDL-{inv_counter}"
                hit["abs_line"] = _approx_line(source, hit["abs_pos"])
                hyp = _build_hypothesis(ws_abs, fn_rec, hit, rel_path)
                inv = _build_invariant_spec(ws_abs, fn_rec, inv_id, hit, rel_path)
                all_hypotheses.append(hyp)
                all_invariants.append(inv)

    out_jsonl = (
        Path(out_path)
        if out_path is not None
        else ws / ".auditooor" / "rounding_drain_hypotheses.jsonl"
    )
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with out_jsonl.open("w", encoding="utf-8") as fh:
        for h in all_hypotheses:
            fh.write(json.dumps(h) + "\n")

    out_inv = (
        Path(out_inv_path)
        if out_inv_path is not None
        else ws / ".auditooor" / "rounding_drain_invariants.jsonl"
    )
    out_inv.parent.mkdir(parents=True, exist_ok=True)
    with out_inv.open("w", encoding="utf-8") as fh:
        for inv in all_invariants:
            fh.write(json.dumps(inv) + "\n")

    return all_hypotheses, all_invariants


# ---------------------------------------------------------------------------
# CLI entry-point.
# ---------------------------------------------------------------------------

def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="RDL: rounding-drain lane hypothesis emitter."
    )
    parser.add_argument("workspace", help="Workspace root path")
    parser.add_argument("--out", default=None, help="Override hypotheses .jsonl path")
    parser.add_argument("--out-inv", default=None, help="Override invariants .jsonl path")
    parser.add_argument("--vmf-json", default=None, help="Override value_moving_functions.json path")
    parser.add_argument(
        "--regen-vmf", action="store_true",
        help="Re-run value-moving-functions.py even if JSON exists",
    )
    args = parser.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 1

    hyps, invs = run_rdl(
        workspace=ws,
        vmf_json_path=args.vmf_json,
        out_path=args.out,
        out_inv_path=args.out_inv,
        regen_vmf=args.regen_vmf,
    )

    out_hyp = (
        Path(args.out) if args.out
        else ws / ".auditooor" / "rounding_drain_hypotheses.jsonl"
    )
    out_inv_ = (
        Path(args.out_inv) if args.out_inv
        else ws / ".auditooor" / "rounding_drain_invariants.jsonl"
    )

    print(f"RDL: {len(hyps)} hypotheses -> {out_hyp}")
    print(f"RDL: {len(invs)} invariant specs -> {out_inv_}")

    by_fn: dict[str, list[dict]] = {}
    for h in hyps:
        key = f"{h['file']}::{h['function']}"
        by_fn.setdefault(key, []).append(h)
    for fn_key, fn_hyps in sorted(by_fn.items()):
        print(f"  {fn_key}:")
        for h in fn_hyps:
            print(f"    [{h['verdict']}] {h['attack_class']} | {h['direction']} | path={h['value_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
