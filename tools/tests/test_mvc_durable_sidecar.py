"""Loop-fix 2026-06-22 (wiring-not-supply): a hand-authored / premade-mutant harness
proven non-vacuous via mutation-verify-coverage.py was written ONLY to a caller-chosen
--out path (or stdout), never to the DURABLE sidecar dir core-coverage-completeness +
function-coverage actually read (.auditooor/mvc_sidecar/*.json). So polygon's 3
mutation-verified step-4b harnesses (PolygonMigration/DefaultEmissionManager/StakeManager)
left core-coverage at 0/40 - the proof evaporated. _persist_durable_sidecar now auto-writes
every non-vacuous kill into that dir so the gate credits it. Only kills are persisted
(matches core-coverage._record_is_kill); deterministic filename (idempotent re-run);
opt-out AUDITOOOR_MVC_NO_AUTO_SIDECAR=1.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "mvc_ds", str(_TOOLS / "mutation-verify-coverage.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mvc_ds"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestDurableSidecar(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp()).resolve()

    def _rec(self, verdict):
        return {
            "schema": "x", "verdict": verdict,
            "mutation_verified": verdict == "non-vacuous",
            "function": "stakeForPOL",
            "source_file": "src/pos-contracts/contracts/staking/stakeManager/StakeManager.sol",
        }

    def test_non_vacuous_persisted_to_mvc_sidecar(self):
        p = self.m._persist_durable_sidecar(self.ws, self._rec("non-vacuous"))
        self.assertIsNotNone(p)
        self.assertTrue(Path(p).is_file())
        self.assertEqual(Path(p).parent, self.ws / ".auditooor" / "mvc_sidecar")
        self.assertIn("stakemanager", Path(p).name.lower())

    def test_vacuous_not_persisted(self):
        self.assertIsNone(self.m._persist_durable_sidecar(self.ws, self._rec("vacuous")))
        self.assertIsNone(self.m._persist_durable_sidecar(self.ws, self._rec("no-baseline")))

    def test_idempotent_filename(self):
        p1 = self.m._persist_durable_sidecar(self.ws, self._rec("non-vacuous"))
        p2 = self.m._persist_durable_sidecar(self.ws, self._rec("non-vacuous"))
        self.assertEqual(p1, p2)  # deterministic -> overwrites itself, no proliferation

    def test_env_opt_out(self):
        import os
        os.environ["AUDITOOOR_MVC_NO_AUTO_SIDECAR"] = "1"
        try:
            self.assertIsNone(self.m._persist_durable_sidecar(self.ws, self._rec("non-vacuous")))
        finally:
            os.environ.pop("AUDITOOOR_MVC_NO_AUTO_SIDECAR", None)

    def test_record_recognized_as_kill_by_core_coverage(self):
        """The persisted record must satisfy core-coverage._record_is_kill so it is
        actually credited (cross-tool contract)."""
        p = self.m._persist_durable_sidecar(self.ws, self._rec("non-vacuous"))
        import json
        rec = json.loads(Path(p).read_text())
        cc_spec = importlib.util.spec_from_file_location(
            "cc", str(_TOOLS / "core-coverage-completeness.py"))
        cc = importlib.util.module_from_spec(cc_spec)
        sys.modules["cc"] = cc
        cc_spec.loader.exec_module(cc)
        self.assertTrue(cc._record_is_kill(rec))
        self.assertTrue(cc._record_cut_paths(rec))  # CUT path extractable


if __name__ == "__main__":
    unittest.main(verbosity=2)
