"""Loop-fix 2026-06-23 (etherfi step-5/hollow): audit-honesty-check's
_mutation_verified_cut_harnesses (which feeds real_inscope_harnesses, the signal that
suppresses fail-stub-harnesses) recognized a real in-scope harness ONLY from the flat
mutation_verify_coverage.v1 schema (schema + verdict==non-vacuous + baseline.status +
mutant_results[].killed). The durable mvc_sidecar CLUSTER schema (mutation_verified +
mutants_killed + harness_path/cut_contracts, ws-relative paths) matched none, so genuine
>=1M-call core campaigns left real_inscope_harnesses empty -> fail-stub-harnesses ->
fail-hollow-not-genuinely-audited. Same serving-join delivery bug as the core-coverage and
engine-harness-proof cluster-sidecar fixes.

Fix: recognize the cluster schema (mutation_verified + a genuine kill + a real on-disk
harness/CUT file). False-green-safe: a vacuous (0-kill) cluster or a record whose paths are
absent from disk credits nothing.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("ah", str(_TOOLS / "audit-honesty-check.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ah"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestHonestyCheckClusterSidecar(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp()).resolve()
        (self.ws / "chimera_harnesses" / "CashSolvency" / "src").mkdir(parents=True)
        (self.ws / "chimera_harnesses" / "CashSolvency" / "src" / "CashSolvencyHarness.sol").write_text("contract H{}")
        (self.ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)

    def _write(self, name, payload):
        (self.ws / ".auditooor" / "mvc_sidecar" / name).write_text(json.dumps(payload))

    def test_cluster_kill_with_relative_harness_path_credited(self):
        self._write("cash.json", {
            "cluster": "CashSolvency", "mutation_verified": True, "mutants_killed": 4,
            "harness_path": "chimera_harnesses/CashSolvency/src/CashSolvencyHarness.sol",
            "mutation_detail": [{"mutant": "x", "mutant_result": "FAIL"}],
            "result": "honest-negative",
        })
        got = self.m._mutation_verified_cut_harnesses(self.ws)
        self.assertTrue(any("CashSolvency" in g for g in got), got)

    def test_vacuous_cluster_not_credited(self):
        self._write("vac.json", {
            "cluster": "CashSolvency", "mutation_verified": True, "mutants_killed": 0,
            "harness_path": "chimera_harnesses/CashSolvency/src/CashSolvencyHarness.sol",
        })
        self.assertEqual(self.m._mutation_verified_cut_harnesses(self.ws), [])

    def test_kill_but_no_ondisk_file_not_credited(self):
        self._write("ghost.json", {
            "cluster": "Ghost", "mutation_verified": True, "mutants_killed": 3,
            "harness_path": "chimera_harnesses/Ghost/Nope.sol",
        })
        self.assertEqual(self.m._mutation_verified_cut_harnesses(self.ws), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
