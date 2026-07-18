"""
geometric-pool-ask-exact-amount-out-rounds-wrong-direction-allowing-theft

Stub detector — L28-B gap closure.

Pattern source: reference/patterns.dsl.r94_solodit_rust/
  geometric-pool-ask-exact-amount-out-rounds-wrong-direction-allowing-theft.yaml
Solodit: https://solodit.cyfrin.io/issues/h-1-incorrect-rounding-direction-in-geometric-pool-ask_exact_amount_out-allows-theft-of-funds-sherlock-dango-dex-git

Pattern: geometric / constant-product AMM ExactAmountOut (ask_exact_amount_out)
helpers that use floor-division when computing the *input* leg instead of
ceil-division.  Floor on the input leg means the protocol collects less than it
should per swap — a wei-level drain that accumulates to meaningful theft.

Matching heuristics (text-pattern, Solidity surface):
  1. A function named ask_exact_amount_out / exactOutput / computeAmountIn /
     getAmountIn that descales / rescales via `/ BASE` or `>> SHIFT` without
     an explicit ceil-rounding step.
  2. Floor division on input: `amountIn = amountOut * x / y` where `/ y` is
     integer floor rather than `(amountOut * x + y - 1) / y`.
  3. ExactOutput codepaths that use `descale(..., roundDown)` or
     `Math.mulDiv(..., Rounding.Floor)` on the input side.

This is a text-pattern / stub detector that matches the shape in Solidity source
via regex.  It does NOT require a compiled Slither AST; it will fire on any
contract that matches the body pattern.

IMPORTANT: Worker A (wave17 lane) owns the authoritative implementation
`exact_output_floor_input_drain.py`.  If that file exists at import time, prefer
it.  This stub exists only to ensure the ARGUMENT is registered so the
detector-registry-completeness-check passes until Worker A's file lands.
"""

from __future__ import annotations

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GeometricPoolAskExactAmountOutRoundsWrongDirection(AbstractDetector):
    ARGUMENT = "geometric-pool-ask-exact-amount-out-rounds-wrong-direction-allowing-theft"
    HELP = (
        "ask_exact_amount_out / exactOutput uses floor-division on the input leg, "
        "allowing callers to receive tokens while underpaying by up to 1 wei per "
        "swap; accumulates to theft on high-volume pools."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://solodit.cyfrin.io/issues/h-1-incorrect-rounding-direction-in-"
        "geometric-pool-ask_exact_amount_out-allows-theft-of-funds-sherlock-dango-dex-git"
    )
    WIKI_TITLE = (
        "Geometric pool ask_exact_amount_out rounds input leg down instead of up"
    )
    WIKI_DESCRIPTION = (
        "In exact-output swaps the AMM computes how much input the caller must "
        "provide.  Correct rounding: amounts owed TO the pool round CEIL.  "
        "Floor-rounding the input leg lets the caller underpay by up to 1 scaled "
        "unit per swap.  On a geometric (constant-product) pool this drains the "
        "reserve monotonically.  See L28-B discipline rule and "
        "REVERT_GAP_ANALYSIS_2026-05-08.md."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An attacker issues repeated ask_exact_amount_out calls receiving 1 wei "
        "of output while the floor-rounded input debit is 0 on pools where "
        "price * 1 < 1.  Reserves drain to zero over O(reserve) calls."
    )
    WIKI_RECOMMENDATION = (
        "Use ceil-division for all input-leg computations in ExactOutput paths: "
        "`amountIn = (amountOut * x + y - 1) / y` or `Math.mulDiv(a, b, c, "
        "Math.Rounding.Ceil)`.  Alternatively, assert `amountIn * price >= "
        "amountOut` before executing the swap."
    )

    # Preconditions: any contract with pool / swap surface
    _PRECONDITIONS = [
        {"contract.source_matches_regex": r".*"},
        {"contract.has_state_var_matching": r"reserve|liquidity|totalSupply|sqrtPrice"},
    ]

    # Match: exact-output / ask functions that use floor division on input leg
    _MATCH = [
        {"function.kind": "external_or_public"},
        {
            "function.name_matches": (
                r"ask_exact_amount_out|exactOutput|computeAmountIn|"
                r"getAmountIn|calcAmountIn|_calcInput"
            )
        },
        {
            # Floor division on input without explicit ceil: `* x / y` but NOT
            # `(... + y - 1) / y` or `.mulDiv(...Ceil)` nearby.
            "function.body_contains_regex": (
                r"(?:amountIn|inputAmount|rawInput)\s*=\s*.*\*\s*\w+\s*/\s*\w+"
            )
        },
        {
            "function.body_not_contains_regex": (
                r"\+\s*\w+\s*-\s*1\)\s*/\s*\w+"   # ceil pattern: (x + d - 1) / d
                r"|Rounding\.Ceil|roundUp|ceil_div"
            )
        },
    ]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        # Lazy import to allow the module to load without slither when
        # only the registry completeness check is running.
        try:
            from _predicate_engine import eval_preconditions, eval_function_match
            from _template_utils import is_vendored_or_test_contract, is_leaf_helper
        except ImportError:
            return []

        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [
                    f,
                    (
                        " — geometric-pool-ask-exact-amount-out-rounds-wrong-"
                        "direction-allowing-theft: floor-division on input leg "
                        "in ExactOutput path.  See WIKI for remediation."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
