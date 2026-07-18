#!/usr/bin/env python3
"""Caveat A: mvc_sidecar SCHEMA-NORMALIZATION consistency across the three readers.

THE SERVING-JOIN BUG this file pins against
-------------------------------------------
Two sidecar schemas record the SAME ground truth (a harness proven non-vacuous by a
real mutant kill):

  (1) AUTO-PRODUCER (mutation-verify-coverage.py::_persist_durable_sidecar):
      keys verdict=='non-vacuous', killed_count, behavior_changing_kill_count,
      genuine_coverage, mutant_results[] - and NO `mutation_verified` key.
  (2) MANUAL-REGISTRATION (register_manual_mvc):
      keys verdict=='non-vacuous', mutation_verified=True, mutants_killed,
      mutant_results[] - and NO `genuine_coverage` key.

A reader keying on `mutation_verified` MISSES schema (1); a reader keying on
`genuine_coverage` MISSES schema (2) - the classic serving-join (genuine evidence
sits in a field the reader does not look at). The fix: ONE canonical predicate
tools/lib/mutation_kill.sidecar_is_genuine that honors verdict=='non-vacuous' AND a
real kill (regardless of schema), wired into ALL THREE readers
(invariant-fuzz-completeness, engine-harness-proof-check, audit-honesty-check).

WHAT THIS TEST ENFORCES
-----------------------
  - BOTH schema variants with a genuine kill -> credited by ALL THREE readers.
  - A VACUOUS variant (verdict!='non-vacuous' / 0 kills) -> credited by NONE
    (fail-closed; the predicate can never manufacture credit that was not earned).
"""
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(modname: str, filename: str):
    spec = importlib.util.spec_from_file_location(modname, str(_TOOLS / filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod  # py3.14: register BEFORE exec_module
    spec.loader.exec_module(mod)
    return mod


# The shared canonical predicate.
_MK = _load("mutation_kill", "lib/mutation_kill.py")


# ---- schema fixtures -------------------------------------------------------
def _auto_producer_genuine(harness_path: str, source_file: str) -> dict:
    """Schema (1): the auto-producer sidecar. verdict + killed_count +
    behavior_changing_kill_count + genuine_coverage; NO mutation_verified key."""
    return {
        "schema": "auditooor.mutation_verify_coverage.v1",
        "verdict": "non-vacuous",
        "killed_count": 2,
        "behavior_changing_kill_count": 2,
        "genuine_coverage": True,
        "harness_path": harness_path,
        "source_file": source_file,
        "function": "deposit",
        "baseline": {"status": "pass", "output_tail": "invariant_solvency runs: 4096 calls: 100000"},
        "mutant_results": [
            {"killed": True, "kill_kind": "behavior-changing",
             "harness_status": "fail",
             "output_tail": "invariant_solvency() FAIL: assertion violated"},
        ],
    }


def _manual_registration_genuine(harness_path: str, source_file: str) -> dict:
    """Schema (2): the manual-registration sidecar. verdict + mutation_verified +
    mutants_killed; NO genuine_coverage key."""
    return {
        "schema": "auditooor.mutation_verify_coverage.v1",
        "verdict": "non-vacuous",
        "mutation_verified": True,
        "mutants_killed": 1,
        "manual_registration": True,
        "harness_path": harness_path,
        "source_file": source_file,
        "function": "withdraw",
        # A GENUINELY-attested manual record carries a FLAT captured baseline
        # (baseline_result + baseline_output_tail) proving a real runner ran - this is
        # what distinguishes it from a hand-authored synthetic nested-only marker. The
        # sidecar-provenance fail-close (tools/lib/mutation_kill.sidecar_manual_attested)
        # requires these; a manual record with only a nested synthetic baseline is
        # advisory-only (uncredited).
        "baseline_result": "PASS",
        "baseline_output_tail": "--- PASS: invariant_conservation (0.05s)\ninvariant_conservation runs: 4096 calls: 100000",
        "baseline": {"status": "pass", "output_tail": "invariant_conservation runs: 4096 calls: 100000"},
        "mutant_results": [
            {"killed": True, "kill_kind": "behavior-changing",
             "harness_status": "fail",
             "output_tail": "invariant_conservation() FAIL (manual mutant-vacuity proof)"},
        ],
    }


def _vacuous(harness_path: str, source_file: str) -> dict:
    """A NON-genuine sidecar: a clean baseline that killed NOTHING. Neither schema's
    credit field is satisfied (verdict!='non-vacuous', no mutation_verified, 0 kills)."""
    return {
        "schema": "auditooor.mutation_verify_coverage.v1",
        "verdict": "vacuous",
        "killed_count": 0,
        "behavior_changing_kill_count": 0,
        "genuine_coverage": False,
        "harness_path": harness_path,
        "source_file": source_file,
        "function": "noop",
        "baseline": {"status": "pass", "output_tail": "[PASS] test result: ok runs: 4096 calls: 100000"},
        "mutant_results": [
            {"killed": False, "kill_kind": "not-a-kill", "harness_status": "pass",
             "output_tail": "[PASS] test result: ok"},
        ],
    }


class TestCanonicalPredicate(unittest.TestCase):
    """The shared predicate itself: both genuine schemas -> True; vacuous -> False."""

    def test_auto_producer_schema_is_genuine(self):
        self.assertTrue(_MK.sidecar_is_genuine(_auto_producer_genuine("h.sol", "S.sol")))

    def test_manual_registration_schema_is_genuine(self):
        self.assertTrue(_MK.sidecar_is_genuine(_manual_registration_genuine("h.sol", "S.sol")))

    def test_vacuous_is_not_genuine(self):
        self.assertFalse(_MK.sidecar_is_genuine(_vacuous("h.sol", "S.sol")))

    def test_fail_closed_corner_cases(self):
        # verdict non-vacuous but ZERO real kills -> not credited (fail-closed).
        self.assertFalse(_MK.sidecar_is_genuine(
            {"verdict": "non-vacuous", "killed_count": 0, "mutant_results": []}))
        # mutation_verified True but ZERO kills -> not credited.
        self.assertFalse(_MK.sidecar_is_genuine(
            {"mutation_verified": True, "mutants_killed": 0}))
        # neither verdict nor mutation_verified, even with a killed row -> not credited.
        self.assertFalse(_MK.sidecar_is_genuine(
            {"killed_count": 3,
             "mutant_results": [{"killed": True, "kill_kind": "behavior-changing"}]}))
        # a panic-only equivalent-mutant kill is NOT a real kill.
        self.assertFalse(_MK.sidecar_is_genuine(
            {"verdict": "non-vacuous",
             "mutant_results": [{"killed": True, "kill_kind": "equivalent-mutant",
                                 "output_tail": "panic: 0x11 arithmetic overflow"}]}))
        # cluster schema: a KILLED mutation_verify row IS a real kill.
        self.assertTrue(_MK.sidecar_is_genuine(
            {"mutation_verified": True,
             "mutation_verify": [{"mutant_id": "A", "verdict": "KILLED"}]}))
        # cluster schema: no KILLED row -> not credited.
        self.assertFalse(_MK.sidecar_is_genuine(
            {"mutation_verified": True,
             "mutation_verify": [{"mutant_id": "A", "verdict": "survived"}]}))
        self.assertFalse(_MK.sidecar_is_genuine({}))
        self.assertFalse(_MK.sidecar_is_genuine(None))


class TestKillMarkerPassOverride(unittest.TestCase):
    """PART1 FAIL-OPEN GUARD: classify_kill_kind / _has_kill_marker must NOT read a
    NEGATED or PASSING tail as a kill, even though the fail substrings ("failing",
    "counterexample", "failed") appear inside the negated/passing phrase. Crediting
    one of these as a behaviour-changing kill is a fail-open over-credit (a passing
    baseline read as a mutant kill). Mirrors the producer's pass-first precedence."""

    # tails that PASS / are NEGATED - must be not-a-kill (no over-credit)
    _NEGATED_PASS_TAILS = [
        "No counterexample found. Property holds.",
        "halmos: 3 paths, no counterexample",
        "medusa: ... no failing sequence",
        "0 failing tests",
        "Symbolic test passed (counterexample search exhausted)",
        "test result: ok. 5 passed; 0 failed",
        "10 test(s) passed, 0 test(s) failed",
        "echidna_solvency: passing",
        "5 passed, 0 failed",
        "no failing tests",
    ]

    # tails that are GENUINE KILLS - must NOT collapse to not-a-kill
    _GENUINE_KILL_TAILS = [
        "Counterexample:",
        "echidna_balance: falsified",
        "[FAIL] testBar()",
        "1 test(s) failed",
        "invariant_solvency() FAIL: assertion violated",
        # mixed multi-test run with a real failure AND a per-test pass line:
        "testA() ok\n5 passed; 1 failed",
        "invariant_x: passing\nechidna_y: failed!",
        "3 test(s) passed, 2 test(s) failed",
    ]

    def test_negated_pass_tails_are_not_kills(self):
        for tail in self._NEGATED_PASS_TAILS:
            with self.subTest(tail=tail):
                self.assertFalse(
                    _MK._has_kill_marker(tail),
                    f"PASS/negated tail must not be a kill marker: {tail!r}")
                self.assertEqual(
                    _MK.classify_kill_kind(tail), "not-a-kill",
                    f"PASS/negated tail must classify not-a-kill: {tail!r}")
                self.assertFalse(
                    _MK.is_behavior_changing_kill(tail),
                    f"PASS/negated tail must not be behaviour-changing: {tail!r}")

    def test_genuine_kills_survive_pass_override(self):
        for tail in self._GENUINE_KILL_TAILS:
            with self.subTest(tail=tail):
                self.assertTrue(
                    _MK._has_kill_marker(tail),
                    f"genuine kill tail must be a kill marker: {tail!r}")
                self.assertNotEqual(
                    _MK.classify_kill_kind(tail), "not-a-kill",
                    f"genuine kill tail must NOT be not-a-kill: {tail!r}")

    def test_sidecar_not_credited_for_negated_kill_row(self):
        # a sidecar whose only "killed" row carries a NEGATED/PASSING tail must NOT
        # be credited (the row is not a real kill once the pass-override applies).
        rec = {
            "verdict": "non-vacuous",
            "mutant_results": [
                {"killed": True, "output_tail": "No counterexample found. Property holds."},
            ],
        }
        self.assertFalse(
            _MK.sidecar_is_genuine(rec),
            "a killed row with a negated/passing tail must not earn credit")

    def test_classify_kill_kind_mirror_agrees(self):
        # the inline mirror in mutation-verify-coverage.py must agree with the lib on
        # the pass-override (so the fallback path cannot re-introduce the false-kill).
        mvc = _load("mvc_passoverride", "mutation-verify-coverage.py")
        for tail in self._NEGATED_PASS_TAILS:
            with self.subTest(tail=tail):
                self.assertEqual(
                    mvc._classify_kill_kind(tail), "not-a-kill",
                    f"producer mirror must classify not-a-kill: {tail!r}")
        for tail in self._GENUINE_KILL_TAILS:
            with self.subTest(tail=tail):
                self.assertNotEqual(
                    mvc._classify_kill_kind(tail), "not-a-kill",
                    f"producer mirror must NOT drop a genuine kill: {tail!r}")


class _ReaderBase(unittest.TestCase):
    """A workspace with a real CUT + harness on disk and a chimera campaign tree, so
    every reader's on-disk file requirement is satisfiable."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="sidecar_consistency_")).resolve()
        # real CUT source on disk
        src = self.ws / "src"
        src.mkdir(parents=True)
        self.cut = src / "Vault.sol"
        self.cut.write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.13;\n"
            "contract Vault { function deposit(uint256 a) public {} }\n",
            encoding="utf-8")
        # a harness dir (chimera campaign) with an invariant property + sibling
        camp = self.ws / "chimera_harnesses" / "Vault"
        camp.mkdir(parents=True)
        self.harness = camp / "VaultHarness.sol"
        self.harness.write_text(
            "contract H { function property_solvency() public returns(bool){ return true; } }\n",
            encoding="utf-8")
        (camp / "Vault.t.sol").write_text(
            "contract T { function invariant_solvency() public {} }\n", encoding="utf-8")
        self.scdir = self.ws / ".auditooor" / "mvc_sidecar"
        self.scdir.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def _write(self, name: str, payload: dict):
        (self.scdir / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _clear(self):
        for p in self.scdir.glob("*.json"):
            p.unlink()


class TestInvariantFuzzReader(_ReaderBase):
    def setUp(self):
        super().setUp()
        self.m = _load("ifc", "invariant-fuzz-completeness.py")

    def _credit(self) -> bool:
        hd = self.harness.parent
        mut, ev = self.m._mvc_sidecar_credit(self.ws, hd)
        return mut

    def test_auto_producer_schema_credited(self):
        self._clear()
        self._write("auto.json", _auto_producer_genuine(
            "chimera_harnesses/Vault/VaultHarness.sol", str(self.cut)))
        self.assertTrue(self._credit(), "auto-producer schema must be credited by invariant-fuzz reader")

    def test_manual_registration_schema_credited(self):
        self._clear()
        self._write("manual.json", _manual_registration_genuine(
            "chimera_harnesses/Vault/VaultHarness.sol", str(self.cut)))
        self.assertTrue(self._credit(), "manual-registration schema must be credited by invariant-fuzz reader")

    def test_vacuous_credited_by_none(self):
        self._clear()
        self._write("vacuous.json", _vacuous(
            "chimera_harnesses/Vault/VaultHarness.sol", str(self.cut)))
        self.assertFalse(self._credit(), "vacuous sidecar must NOT be credited by invariant-fuzz reader")


class TestEngineHarnessProofReader(_ReaderBase):
    def setUp(self):
        super().setUp()
        self.m = _load("ehp_consistency", "engine-harness-proof-check.py")

    def _credit(self, payload: dict) -> bool:
        return self.m._record_is_nonvacuous(payload)

    def test_auto_producer_schema_credited(self):
        self.assertTrue(self._credit(_auto_producer_genuine("h.sol", str(self.cut))),
                        "auto-producer schema must be credited by engine-harness-proof reader")

    def test_manual_registration_schema_credited(self):
        self.assertTrue(self._credit(_manual_registration_genuine("h.sol", str(self.cut))),
                        "manual-registration schema must be credited by engine-harness-proof reader")

    def test_vacuous_credited_by_none(self):
        self.assertFalse(self._credit(_vacuous("h.sol", str(self.cut))),
                         "vacuous sidecar must NOT be credited by engine-harness-proof reader")


class TestAuditHonestyReader(_ReaderBase):
    def setUp(self):
        super().setUp()
        self.m = _load("ahc_consistency", "audit-honesty-check.py")

    def _credited_labels(self) -> list:
        return self.m._mutation_verified_cut_harnesses(self.ws)

    def test_auto_producer_schema_credited(self):
        self._clear()
        self._write("auto.json", _auto_producer_genuine(
            "chimera_harnesses/Vault/VaultHarness.sol", str(self.cut)))
        self.assertTrue(self._credited_labels(),
                        "auto-producer schema must be credited by audit-honesty reader")

    def test_manual_registration_schema_credited(self):
        self._clear()
        self._write("manual.json", _manual_registration_genuine(
            "chimera_harnesses/Vault/VaultHarness.sol", str(self.cut)))
        self.assertTrue(self._credited_labels(),
                        "manual-registration schema must be credited by audit-honesty reader")

    def test_vacuous_credited_by_none(self):
        self._clear()
        self._write("vacuous.json", _vacuous(
            "chimera_harnesses/Vault/VaultHarness.sol", str(self.cut)))
        self.assertEqual(self._credited_labels(), [],
                         "vacuous sidecar must NOT be credited by audit-honesty reader")


class TestAllReadersAgree(_ReaderBase):
    """The load-bearing consistency property: for EACH schema variant, ALL THREE
    readers reach the SAME credit decision (all-credit for genuine, none-credit for
    vacuous). This is what kills the serving-join."""

    def setUp(self):
        super().setUp()
        self.ifc = _load("ifc_agree", "invariant-fuzz-completeness.py")
        self.ehp = _load("ehp_agree", "engine-harness-proof-check.py")
        self.ahc = _load("ahc_agree", "audit-honesty-check.py")

    def _all_three(self, payload: dict) -> tuple:
        self._clear()
        self._write("rec.json", payload)
        hd = self.harness.parent
        ifc_mut, _ = self.ifc._mvc_sidecar_credit(self.ws, hd)
        ehp_ok = self.ehp._record_is_nonvacuous(payload)
        ahc_ok = bool(self.ahc._mutation_verified_cut_harnesses(self.ws))
        return ifc_mut, ehp_ok, ahc_ok

    def test_auto_producer_credited_by_all_three(self):
        rel = "chimera_harnesses/Vault/VaultHarness.sol"
        self.assertEqual(self._all_three(_auto_producer_genuine(rel, str(self.cut))),
                         (True, True, True))

    def test_manual_registration_credited_by_all_three(self):
        rel = "chimera_harnesses/Vault/VaultHarness.sol"
        self.assertEqual(self._all_three(_manual_registration_genuine(rel, str(self.cut))),
                         (True, True, True))

    def test_vacuous_credited_by_none_of_three(self):
        rel = "chimera_harnesses/Vault/VaultHarness.sol"
        self.assertEqual(self._all_three(_vacuous(rel, str(self.cut))),
                         (False, False, False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
