#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-INVARIANT-FUZZ-GATE registered via agent-pathspec-register.py -->
"""Guard: invariant-fuzz ASSET-coverage credits fuzz-DEPTH, not mutation-QUALITY.

Defect (nuva 2026-07): the asset-coverage gate (floor MIN_CALLS=1_000_000 medusa /
MIN_CALLS_ECHIDNA=500_000) credited an mvc_sidecar's source_file/cut as "covered" on
the basis of mutation-verification ALONE, with NO call-floor check. A shallow harness
(forge invariant runs:256 = 128k calls, emitted mode='manual-mutant-harness',
mutation_verified=true, NO campaign_calls) therefore closed a >=1M asset gap it never
met - DepositorFactory.sol + WithdrawalFactory.sol were falsely credited, while the
genuine >=1M record (medusa campaign_calls=1_204_887) is what SHOULD be required.

Fix: `_sidecar_cleared_call_floor` decouples depth from mutation-quality and both the
`_fuzzed_cut_files` source_file/cut credit AND the `_mutation_verified_harness_sources`
transitive credit gate on it. A no-campaign sidecar no longer vacuously passes.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "ifc_depth", str(_TOOLS / "invariant-fuzz-completeness.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["ifc_depth"] = m
spec.loader.exec_module(m)


def _write(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj) if not isinstance(obj, str) else obj, encoding="utf-8")


class TestDepthNotMutation(unittest.TestCase):
    def _ws(self, sidecars, inscope):
        d = tempfile.mkdtemp()
        ws = Path(d)
        # in-scope value-moving .sol files (for the filename-fallback + rel-norm)
        man = ws / ".auditooor" / "inscope_units.jsonl"
        man.parent.mkdir(parents=True, exist_ok=True)
        man.write_text("\n".join(json.dumps({"file": f}) for f in inscope), encoding="utf-8")
        for name, obj in sidecars.items():
            _write(ws / ".auditooor" / "mvc_sidecar" / f"{name}.json", obj)
        return ws

    def test_helper_call_floor_matrix(self):
        # (a) medusa 1.2M mutation-verified -> clears
        self.assertTrue(m._sidecar_cleared_call_floor(Path("/x"), {
            "mutation_verified": True, "engine": "medusa", "campaign_calls": 1_200_000}))
        # (b) manual-mutant-harness, mutation-verified, NO campaign_calls -> does NOT clear
        self.assertFalse(m._sidecar_cleared_call_floor(Path("/x"), {
            "mutation_verified": True, "mode": "manual-mutant-harness", "verdict": "non-vacuous"}))
        # (c) echidna 600k -> clears (500k floor)
        self.assertTrue(m._sidecar_cleared_call_floor(Path("/x"), {
            "mutation_verified": True, "engine": "echidna", "campaign_calls": 600_000}))
        # (d) forge invariant runs:256 = 128k -> does NOT clear the medusa floor
        self.assertFalse(m._sidecar_cleared_call_floor(Path("/x"), {
            "mutation_verified": True, "mode": "manual-mutant-harness", "calls": 128_000}))
        # echidna but only 400k -> below echidna floor
        self.assertFalse(m._sidecar_cleared_call_floor(Path("/x"), {
            "engine": "echidna", "campaign_calls": 400_000}))

    def test_fuzzed_cut_files_gates_on_depth(self):
        inscope = [
            "src/DepositorFactory.sol",
            "src/WithdrawalFactory.sol",
            "src/Depositor.sol",
        ]
        sidecars = {
            # 128k forge mutant harness -> must NOT credit its source_file
            "mvc-depositorfactory": {
                "source_file": "src/DepositorFactory.sol",
                "mutation_verified": True, "verdict": "non-vacuous",
                "mode": "manual-mutant-harness", "manual_registration": True,
                "harness_path": "chimera_harnesses/Factories/DepositorFactory_Invariant.t.sol",
            },
            # another shallow forge harness with an explicit 128k count
            "mvc-withdrawalfactory": {
                "source_file": "src/WithdrawalFactory.sol",
                "mutation_verified": True, "mode": "manual-mutant-harness",
                "calls": 128_000,
            },
            # genuine 1.2M medusa campaign -> MUST stay covered
            "depositor_core": {
                "cut": "src/Depositor.sol", "contract": "DepositorHandler",
                "mutation_verified": True, "engine": "medusa",
                "campaign_calls": 1_204_887,
            },
        }
        ws = self._ws(sidecars, inscope)
        covered = m._fuzzed_cut_files(ws)
        self.assertIn("src/Depositor.sol", covered,
                      "1.2M medusa campaign must remain covered")
        self.assertNotIn("src/DepositorFactory.sol", covered,
                         "128k forge mutant harness must NOT close the >=1M asset gap")
        self.assertNotIn("src/WithdrawalFactory.sol", covered,
                         "128k forge mutant harness must NOT close the >=1M asset gap")

    def test_echidna_and_receipt_paths_still_credit(self):
        inscope = ["src/Pool.sol", "src/Vault.sol"]
        sidecars = {
            "mvc-pool": {
                "source_file": "src/Pool.sol", "mutation_verified": True,
                "engine": "echidna", "campaign_calls": 600_000,
            },
        }
        ws = self._ws(sidecars, inscope)
        # external-receipt-proven case: sidecar has no campaign, but a credited
        # fuzz_campaign_receipt campaign for its harness cleared the floor.
        rec = {
            "campaigns": [{
                "harness": "chimera_harnesses/Vault/Vault.sol",
                "name": "vault", "engine": "medusa",
                "result": {"calls": 1_500_000},
            }],
        }
        _write(ws / ".auditooor" / "fuzz_campaign_receipt.json", rec)
        vault_sidecar = {
            "source_file": "src/Vault.sol", "mutation_verified": True,
            "mode": "manual-mutant-harness",
            "harness_path": "chimera_harnesses/Vault/Vault.sol",
        }
        _write(ws / ".auditooor" / "mvc_sidecar" / "mvc-vault.json", vault_sidecar)
        covered = m._fuzzed_cut_files(ws)
        self.assertIn("src/Pool.sol", covered, "echidna 600k must credit")
        self.assertIn("src/Vault.sol", covered,
                      "receipt-proven >=1M harness must lend depth credit")


if __name__ == "__main__":
    unittest.main()
