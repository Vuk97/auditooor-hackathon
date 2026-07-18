#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-CORE-COVERAGE-GATE registered via agent-pathspec-register.py -->
"""Guard: core-coverage-completeness credits a SUBSTITUTED / equivalent-mutant /
thin-wrapper core slot ONLY when it carries a machine-checkable 0-mutability proof.

THE FALSE-GREEN THIS CLOSES
---------------------------
A core contract (e.g. the SSV updateNetworkFee pure setter) can be claimed
"covered" by SUBSTITUTION / treating it as an equivalent-mutant / thin-wrapper
("no behaviour-changing mutant can exist, so a real kill is impossible"). Before
this fix, such a record could smuggle credit through the ordinary kill path - a
verdict token or a spurious ``mutants_killed: 1`` counter on a substitution claim
was treated as a genuine kill. That let a "we gave up / it is a thin wrapper"
claim pass as coverage WITHOUT proving the contract is genuinely 0-mutable.

THE FIX (proven, not assumed)
-----------------------------
A substitution-flagged record is routed EXCLUSIVELY through the 0-mutability proof
gate. It is credited ONLY when it evidences an attempted mutation campaign that
produced ONLY equivalent-mutant verdicts: ``mutants_attempted >= 1``, every detail
row classified equivalent-mutant (reusing tools/lib/mutation_kill), 0
behaviour-changing kills, 0 survived, and a cited per-function reason.

BOTH DIRECTIONS (required by the never-false-pass charter):
  - WITH a genuine 0-mutability proof  -> the substituted core slot PASSES.
  - the SAME slot WITHOUT the proof    -> FAILS (gate stays red).
  - additive: a real mutation-verified (behaviour-changing kill) core harness
    still PASSES unchanged.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "ccc_sub", str(_TOOLS / "core-coverage-completeness.py"))
ccc = importlib.util.module_from_spec(_spec)
sys.modules["ccc_sub"] = ccc
_spec.loader.exec_module(ccc)


def _ws() -> Path:
    return Path(tempfile.mkdtemp())


def _write_src(ws: Path, rel: str):
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("// SPDX-License-Identifier: MIT\n"
                 "contract C { function updateNetworkFee(uint256 f) public {} }\n")


def _write_vmf(ws: Path, core_file: str):
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    (d / "value_moving_functions.json").write_text(json.dumps({
        "workspace": str(ws),
        "function_count": 1,
        "functions": [
            {"file": core_file, "function": "updateNetworkFee", "language": "sol",
             "transfer_hit": True, "ledger_write_hit": True},
        ],
    }), encoding="utf-8")


def _write_mutation_records(ws: Path, records: list):
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    (d / "mutation_verify_coverage.json").write_text(
        json.dumps({"results": records}), encoding="utf-8")


# A genuine equivalent-mutant output_tail (EVM-enforced panic, NO behaviour-
# changing assertion frame) - classify_kill_kind judges this "equivalent-mutant".
_EQUIV_TAIL = (
    "Running 1 test for test/Inv.t.sol:Inv\n"
    "[FAIL. Reason: panic: arithmetic underflow or overflow (0x11)]\n"
)
# A genuine behaviour-changing kill tail (a real property assertion fired).
_BEHAVIOR_TAIL = (
    "Running 1 test for test/Inv.t.sol:Inv\n"
    "[FAIL. Reason: assertion failed] invariant_feeConserved() (runs: 1)\n"
)


class TestSubstitutionProof(unittest.TestCase):

    # ---- DIRECTION 1: substitution WITH a genuine 0-mutability proof PASSES ----
    def test_substitution_with_zero_mutability_proof_PASSES(self):
        ws = _ws()
        _write_src(ws, "src/NetworkFee.sol")
        _write_vmf(ws, "src/NetworkFee.sol")
        _write_mutation_records(ws, [{
            "source_file": "src/NetworkFee.sol",
            "function": "updateNetworkFee",
            "verdict": "equivalent-mutant-only",     # substitution claim
            "zero_mutability_proof": {
                "mutants_attempted": 2,
                "behavior_changing_kills": 0,
                "survived": 0,
                "reason": "pure setter writing a single storage slot; every "
                          "mutant only flips an EVM-enforced panic",
                "mutant_results": [
                    {"mutant_id": "m1", "kill_kind": "equivalent-mutant",
                     "output_tail": _EQUIV_TAIL},
                    {"mutant_id": "m2", "kill_kind": "equivalent-mutant",
                     "output_tail": _EQUIV_TAIL},
                ],
            },
        }])
        r = ccc.evaluate(ws)
        self.assertEqual(r["verdict"], "pass-core-covered", r)
        self.assertIn("src/NetworkFee.sol", r["covered_core"])

    # ---- DIRECTION 2: the SAME slot WITHOUT the proof FAILS ----
    def test_substitution_without_proof_FAILS(self):
        ws = _ws()
        _write_src(ws, "src/NetworkFee.sol")
        _write_vmf(ws, "src/NetworkFee.sol")
        # The dangerous shape: a substitution claim that even carries a spurious
        # kill verdict + mutants_killed counter, but NO 0-mutability proof.
        _write_mutation_records(ws, [{
            "source_file": "src/NetworkFee.sol",
            "function": "updateNetworkFee",
            "verdict": "equivalent-mutant-only",
            "substituted": True,
            "mutants_killed": 1,          # would have smuggled credit pre-fix
            "non_vacuous": True,          # ditto
        }])
        r = ccc.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-core-coverage-periphery-only", r)
        self.assertEqual(r["covered_core_count"], 0)
        self.assertIn("src/NetworkFee.sol", r["uncovered_core"])

    # ---- a proof that is internally inconsistent must NOT credit ----
    def test_proof_with_behavior_changing_kill_does_NOT_credit(self):
        # behavior_changing_kills != 0 -> the contract IS mutable; "0-mutable" is a
        # lie. Must NOT pass (needs a REAL harness, not a substitution).
        ws = _ws()
        _write_src(ws, "src/NetworkFee.sol")
        _write_vmf(ws, "src/NetworkFee.sol")
        _write_mutation_records(ws, [{
            "source_file": "src/NetworkFee.sol",
            "verdict": "equivalent-mutant-only",
            "zero_mutability_proof": {
                "mutants_attempted": 2,
                "behavior_changing_kills": 1,   # contradicts 0-mutability
                "survived": 0,
                "reason": "claimed thin wrapper",
                "mutant_results": [
                    {"kill_kind": "behavior-changing", "output_tail": _BEHAVIOR_TAIL},
                    {"kill_kind": "equivalent-mutant", "output_tail": _EQUIV_TAIL},
                ],
            },
        }])
        self.assertEqual(ccc.evaluate(ws)["verdict"],
                         "fail-core-coverage-periphery-only")

    def test_proof_with_survived_mutant_does_NOT_credit(self):
        # survived != 0 -> a mutant escaped detection = vacuity, not 0-mutability.
        ws = _ws()
        _write_src(ws, "src/NetworkFee.sol")
        _write_vmf(ws, "src/NetworkFee.sol")
        _write_mutation_records(ws, [{
            "source_file": "src/NetworkFee.sol",
            "verdict": "equivalent-mutant-only",
            "zero_mutability_proof": {
                "mutants_attempted": 2,
                "behavior_changing_kills": 0,
                "survived": 1,                  # a mutant escaped
                "reason": "claimed thin wrapper",
                "mutant_results": [
                    {"kill_kind": "equivalent-mutant", "output_tail": _EQUIV_TAIL},
                ],
            },
        }])
        self.assertEqual(ccc.evaluate(ws)["verdict"],
                         "fail-core-coverage-periphery-only")

    def test_proof_with_zero_attempted_does_NOT_credit(self):
        # A campaign that attempted ZERO mutants proves nothing.
        ws = _ws()
        _write_src(ws, "src/NetworkFee.sol")
        _write_vmf(ws, "src/NetworkFee.sol")
        _write_mutation_records(ws, [{
            "source_file": "src/NetworkFee.sol",
            "verdict": "equivalent-mutant-only",
            "zero_mutability_proof": {
                "mutants_attempted": 0,
                "behavior_changing_kills": 0,
                "survived": 0,
                "reason": "we did not actually run any mutants",
                "mutant_results": [],
            },
        }])
        self.assertEqual(ccc.evaluate(ws)["verdict"],
                         "fail-core-coverage-periphery-only")

    def test_proof_with_no_reason_does_NOT_credit(self):
        ws = _ws()
        _write_src(ws, "src/NetworkFee.sol")
        _write_vmf(ws, "src/NetworkFee.sol")
        _write_mutation_records(ws, [{
            "source_file": "src/NetworkFee.sol",
            "verdict": "equivalent-mutant-only",
            "zero_mutability_proof": {
                "mutants_attempted": 1,
                "behavior_changing_kills": 0,
                "survived": 0,
                # reason missing
                "mutant_results": [
                    {"kill_kind": "equivalent-mutant", "output_tail": _EQUIV_TAIL},
                ],
            },
        }])
        self.assertEqual(ccc.evaluate(ws)["verdict"],
                         "fail-core-coverage-periphery-only")

    def test_proof_with_unproven_equivalent_row_does_NOT_credit(self):
        # A detail row that is NOT a genuine equivalent-mutant (e.g. a bare claim
        # with a non-equivalent tail) invalidates the proof. classify_kill_kind on
        # _BEHAVIOR_TAIL returns behavior-changing, not equivalent-mutant.
        ws = _ws()
        _write_src(ws, "src/NetworkFee.sol")
        _write_vmf(ws, "src/NetworkFee.sol")
        _write_mutation_records(ws, [{
            "source_file": "src/NetworkFee.sol",
            "verdict": "equivalent-mutant-only",
            "zero_mutability_proof": {
                "mutants_attempted": 1,
                "behavior_changing_kills": 0,
                "survived": 0,
                "reason": "claimed thin wrapper",
                "mutant_results": [
                    # no kill_kind tag; tail is behaviour-changing, not equivalent
                    {"output_tail": _BEHAVIOR_TAIL},
                ],
            },
        }])
        self.assertEqual(ccc.evaluate(ws)["verdict"],
                         "fail-core-coverage-periphery-only")

    def test_proof_fewer_rows_than_attempted_does_NOT_credit(self):
        # Claim "5 attempted, all equivalent" but evidence only 1 row -> reject.
        ws = _ws()
        _write_src(ws, "src/NetworkFee.sol")
        _write_vmf(ws, "src/NetworkFee.sol")
        _write_mutation_records(ws, [{
            "source_file": "src/NetworkFee.sol",
            "verdict": "equivalent-mutant-only",
            "zero_mutability_proof": {
                "mutants_attempted": 5,
                "behavior_changing_kills": 0,
                "survived": 0,
                "reason": "claimed thin wrapper",
                "mutant_results": [
                    {"kill_kind": "equivalent-mutant", "output_tail": _EQUIV_TAIL},
                ],
            },
        }])
        self.assertEqual(ccc.evaluate(ws)["verdict"],
                         "fail-core-coverage-periphery-only")

    # ---- ADDITIVE: a real behaviour-changing-kill core harness still PASSES ----
    def test_real_mutation_verified_core_harness_still_PASSES(self):
        ws = _ws()
        _write_src(ws, "src/NetworkFee.sol")
        _write_vmf(ws, "src/NetworkFee.sol")
        _write_mutation_records(ws, [{
            "source_file": "src/NetworkFee.sol",
            "function": "updateNetworkFee",
            "verdict": "non-vacuous",        # genuine kill, NOT a substitution
            "mutation_verified": True,
        }])
        r = ccc.evaluate(ws)
        self.assertEqual(r["verdict"], "pass-core-covered", r)
        self.assertIn("src/NetworkFee.sol", r["covered_core"])

    # ---- a substitution proof on a PERIPHERY file does not cover the core ----
    def test_substitution_proof_on_periphery_does_NOT_cover_core(self):
        ws = _ws()
        _write_src(ws, "src/NetworkFee.sol")
        _write_src(ws, "src/Logger.sol")
        _write_vmf(ws, "src/NetworkFee.sol")          # core = the fee setter
        _write_mutation_records(ws, [{
            "source_file": "src/Logger.sol",          # proof targets periphery
            "verdict": "equivalent-mutant-only",
            "zero_mutability_proof": {
                "mutants_attempted": 1,
                "behavior_changing_kills": 0,
                "survived": 0,
                "reason": "logger is a thin wrapper",
                "mutant_results": [
                    {"kill_kind": "equivalent-mutant", "output_tail": _EQUIV_TAIL},
                ],
            },
        }])
        r = ccc.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-core-coverage-periphery-only", r)
        self.assertIn("src/NetworkFee.sol", r["uncovered_core"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
