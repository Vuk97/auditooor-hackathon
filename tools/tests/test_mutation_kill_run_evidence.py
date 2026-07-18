#!/usr/bin/env python3
"""E2 regression: a cluster mutation-KILL row needs RUN EVIDENCE.

Locks in the fix for a CONFIRMED SSV coverage-theater fabrication: the
ssv_eb_accounting.json mvc_sidecar carried a mutation_verify[] list of 3 rows,
each `verdict=='KILLED'` with output_tail=None, evidence_logs=None, mutant=None,
and NO property-name hit anywhere in the run logs - the mutants were NEVER RUN.
tools/lib/mutation_kill.py::_sidecar_has_real_kill branch (c) credited such a row
on the `verdict=='killed'` STRING ALONE.

Behaviour under test (advisory-first + gate graduated to DEFAULT-ON under L37).
The 4-case matrix (env AUDITOOOR_MUTATION_KILL_RUN_EVIDENCE_STRICT x AUDITOOOR_L37_STRICT):
  1. env unset + L37 set           -> ENFORCED  (new default; no-evidence KILL rejected);
  2. env unset + no L37            -> advisory  (legacy token-string credit preserved);
  3. env=0 (opt-out) even under L37 -> advisory  (escape hatch, legacy credit);
  4. env=1 (opt-in)                -> ENFORCED  (regardless of L37).
When ENFORCED: a KILLED row with NO run evidence is NOT credited; a KILLED row WITH
run evidence (non-empty output_tail / evidence_logs / a run counter) still IS credited
(NEVER-FALSE-PASS). The typed claim fields present in the fabrication (kill_sequence,
calls_to_kill, property_killed) never count as run evidence.
"""
import importlib.util
import os
import sys
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "mutation_kill", str(_TOOLS / "lib" / "mutation_kill.py"))
mk = importlib.util.module_from_spec(spec)
sys.modules["mutation_kill"] = mk
spec.loader.exec_module(mk)

_STRICT_ENV = "AUDITOOOR_MUTATION_KILL_RUN_EVIDENCE_STRICT"
_L37_ENV = "AUDITOOOR_L37_STRICT"

# The confirmed SSV fabrication shape: a cluster mutation_verify[] of KILLED rows
# with NO run evidence (only typed claims). No verdict/mutation_verified top-level
# flag - genuineness is carried STRUCTURALLY by the non-empty mutation_verify[].
_FABRICATED_SIDECAR = {
    "schema_version": "auditooor.mvc_sidecar.cluster.v1",
    "harness_path": "test/echidna/SSVEBAccountingEchidna.sol",
    "mutation_verify": [
        {"mutant_id": "MUTANT-A", "verdict": "KILLED",
         "property_killed": "echidna_mutant_a_floor_required",
         "kill_sequence": "SSVEBAccountingMutantA.action_probe(0,5,0,1690)",
         "calls_to_kill": 84},
        {"mutant_id": "MUTANT-B", "verdict": "KILLED",
         "property_killed": "echidna_mutant_b_cross_cluster_replay",
         "calls_to_kill": 84},
    ],
}


class TestMutationKillRunEvidence(unittest.TestCase):
    def setUp(self):
        # Deterministic base: BOTH the gate env and the L37 umbrella cleared so an
        # "env unset" test is unambiguously the "unset + no L37 -> advisory" case.
        os.environ.pop(_STRICT_ENV, None)
        os.environ.pop(_L37_ENV, None)

    def tearDown(self):
        os.environ.pop(_STRICT_ENV, None)
        os.environ.pop(_L37_ENV, None)

    # ---- 4-case gate-strict matrix on the fabrication (no run evidence) ----
    def test_case2_unset_no_l37_credits_token_string_kill(self):
        # CASE 2 (env unset + no L37): the fabrication still credits (legacy
        # behaviour preserved for a bare non-strict / library caller).
        self.assertTrue(mk._sidecar_has_real_kill(_FABRICATED_SIDECAR))
        self.assertTrue(mk.sidecar_is_genuine(_FABRICATED_SIDECAR))

    def test_case1_unset_under_l37_rejects_no_evidence_kill(self):
        # CASE 1 (env unset + L37 set): the NEW default - the strict audit umbrella
        # enforces run-evidence WITHOUT the operator naming the per-gate env.
        os.environ[_L37_ENV] = "1"
        self.assertFalse(mk._sidecar_has_real_kill(_FABRICATED_SIDECAR))
        self.assertFalse(mk.sidecar_is_genuine(_FABRICATED_SIDECAR))

    def test_case3_optout_under_l37_credits_token_string_kill(self):
        # CASE 3 (env=0 opt-out, even under L37): escape hatch restores legacy credit.
        os.environ[_L37_ENV] = "1"
        os.environ[_STRICT_ENV] = "0"
        self.assertTrue(mk._sidecar_has_real_kill(_FABRICATED_SIDECAR))
        self.assertTrue(mk.sidecar_is_genuine(_FABRICATED_SIDECAR))

    def test_case4_explicit_optin_rejects_no_evidence_kill(self):
        # CASE 4 (env=1 explicit opt-in): enforced regardless of L37 (here L37 unset).
        os.environ[_STRICT_ENV] = "1"
        self.assertFalse(mk._sidecar_has_real_kill(_FABRICATED_SIDECAR))
        self.assertFalse(mk.sidecar_is_genuine(_FABRICATED_SIDECAR))

    def test_strict_claim_fields_are_not_run_evidence(self):
        # kill_sequence / calls_to_kill / property_killed are typed claims, NOT run
        # evidence: a runner writes output_tail / a run counter, not these.
        os.environ[_STRICT_ENV] = "1"
        row = {"verdict": "KILLED", "kill_sequence": "H.probe(1)",
               "calls_to_kill": 84, "property_killed": "echidna_x"}
        self.assertFalse(mk._cluster_row_has_run_evidence(row))
        self.assertFalse(mk._sidecar_has_real_kill({"mutation_verify": [row]}))

    # ---- STRICT never-false-pass: a KILLED row WITH run evidence still credits ----
    def test_strict_credits_kill_with_output_tail(self):
        os.environ[_STRICT_ENV] = "1"
        d = {"mutation_verify": [
            {"verdict": "KILLED",
             "output_tail": "echidna_mutant_a_floor_required: failed! with counterexample"}]}
        self.assertTrue(mk._sidecar_has_real_kill(d))

    def test_strict_credits_kill_with_evidence_logs(self):
        os.environ[_STRICT_ENV] = "1"
        d = {"mutation_verify": [
            {"verdict": "KILLED", "evidence_logs": [".auditooor/fuzz_logs/mutant_a.log"]}]}
        self.assertTrue(mk._sidecar_has_real_kill(d))

    def test_strict_credits_kill_with_run_counter(self):
        os.environ[_STRICT_ENV] = "1"
        d = {"mutation_verify": [{"verdict": "KILLED", "mutants_run": 1}]}
        self.assertTrue(mk._sidecar_has_real_kill(d))
        d2 = {"mutation_detail": [{"mutant_result": "FAIL", "calls": 84}]}
        self.assertTrue(mk._sidecar_has_real_kill(d2))

    # ---- STRICT must NOT touch the OTHER (evidence-bearing) credit branches ----
    def test_strict_does_not_affect_counter_branch(self):
        # branch (a): a positive killed counter is un-fakeable ground truth and is
        # unaffected by the cluster-row strict predicate.
        os.environ[_STRICT_ENV] = "1"
        d = {"verdict": "non-vacuous", "killed_count": 2}
        self.assertTrue(mk._sidecar_has_real_kill(d))
        self.assertTrue(mk.sidecar_is_genuine(d))

    def test_strict_does_not_affect_mutant_results_branch(self):
        # branch (b): a genuine behaviour-changing mutant_results row is unaffected.
        os.environ[_STRICT_ENV] = "1"
        d = {"verdict": "non-vacuous", "mutant_results": [
            {"killed": True, "kill_kind": "behavior-changing"}]}
        self.assertTrue(mk._sidecar_has_real_kill(d))

    def test_strict_still_rejects_zero_kill_record(self):
        # a record with NO kills is not credited in either mode (fail-closed).
        for strict in (None, "1"):
            os.environ.pop(_STRICT_ENV, None)
            if strict:
                os.environ[_STRICT_ENV] = strict
            d = {"mutation_verify": [{"verdict": "SURVIVED"}]}
            self.assertFalse(mk._sidecar_has_real_kill(d))


if __name__ == "__main__":
    unittest.main()
