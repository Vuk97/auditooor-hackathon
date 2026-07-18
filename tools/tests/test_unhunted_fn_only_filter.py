#!/usr/bin/env python3
"""Guard: the unhunted gate drops fn-only corpus-hunt-fuel leads that are
HARNESS / non-production fns (echidna action_*, test-only helpers) but KEEPS
production fns (incl internal helpers) - the SSV _verifyEBRoots vs
action_cross_cluster_proof_replay split."""
import importlib.util, sys, unittest
from pathlib import Path
_spec = importlib.util.spec_from_file_location(
    "ug", str(Path(__file__).resolve().parent.parent / "unhunted-surface-followthrough-gate.py"))
ug = importlib.util.module_from_spec(_spec); sys.modules["ug"] = ug; _spec.loader.exec_module(ug)


class T(unittest.TestCase):
    def _rows(self, *titles):
        return [{"title": t, "id": "x", "source": "s"} for t in titles]

    def test_harness_prefix_dropped(self):
        rows = self._rows("corpus-hunt-fuel: INV-1 (bridge_replay) @ action_cross_cluster_proof_replay")
        kept, _, oou = ug._fc_credit_filter(rows, {("a.sol", "f")}, set(), {"f"})
        self.assertEqual(kept, []); self.assertEqual(oou, 1)

    def test_non_production_fn_dropped(self):
        rows = self._rows("corpus-hunt-fuel: INV-2 (x) @ _boundAmount")
        kept, _, oou = ug._fc_credit_filter(rows, {("a.sol", "f")}, set(), {"verifyebroots", "f"})
        self.assertEqual(kept, []); self.assertEqual(oou, 1)   # not in production set

    def test_production_internal_fn_kept(self):
        rows = self._rows("corpus-hunt-fuel: INV-3 (crypto_signing) @ _verifyEBRoots")
        kept, _, _ = ug._fc_credit_filter(rows, {("a.sol", "f")}, set(), {"_verifyebroots"})
        self.assertEqual(len(kept), 1)                          # production internal => kept

    def test_no_production_set_keeps_conservatively(self):
        rows = self._rows("corpus-hunt-fuel: INV-4 (x) @ someInternalThing")
        kept, _, _ = ug._fc_credit_filter(rows, {("a.sol", "f")}, set(), None)
        self.assertEqual(len(kept), 1)                          # unknown set => keep


if __name__ == "__main__":
    unittest.main()
