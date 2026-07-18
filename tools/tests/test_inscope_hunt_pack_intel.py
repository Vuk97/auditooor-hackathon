# <!-- r36-rebuttal: lane FIX-HYBRID-PACK-INTEL registered via agent-pathspec-register.py -->
"""Guard: inscope-hunt-batch-builder --with-pack-intel HYBRID mode.
Empirical basis (optimism 2026-06-16 3-arm experiment): pack-ONLY hunting produced 5/10
false-positive HIGHs (hallucinated un-seen guards; the pack has no function body); hybrid
(pack-prime + real-source read) added signal at zero R76 cost. So a pack-primed task MUST
still hard-require the source read, must carry the hallucination warning, and must never
present pack intel AS code."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "inscope-hunt-batch-builder.py"


def _load():
    spec = importlib.util.spec_from_file_location("inscope_hunt_batch_builder", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["inscope_hunt_batch_builder"] = m
    spec.loader.exec_module(m)
    return m


class HybridPackIntelTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor" / "pre_flight_packs").mkdir(parents=True)
        # in-scope manifest: two contracts-bedrock/src fns, one with a pack, one without
        rows = [
            {"file": "src/packages/contracts-bedrock/src/L1/Portal.sol", "function": "finalize", "lang": "solidity"},
            {"file": "src/packages/contracts-bedrock/src/L1/Portal.sol", "function": "prove", "lang": "solidity"},
        ]
        (self.ws / ".auditooor" / "inscope_units.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        # a pack for Portal.finalize ONLY
        (self.ws / ".auditooor" / "pre_flight_packs" / "pre_flight_pack_Portal_finalize.json").write_text(
            json.dumps({
                "per_function_hunter_brief": "check the withdrawal replay guard and the proof-maturity delay",
                "attack_class_evidence": "double-finalize / replay",
                "function_shape": {"function_signature": "function finalize(...) external"},
                "source_ref": "src/packages/contracts-bedrock/src/L1/Portal.sol:474",
            }), encoding="utf-8")

    def _tasks(self, with_pack):
        t, err = self.m.build_tasks(self.ws, None, False, None, with_pack)
        self.assertIsNone(err, err)
        return {x["function_anchor"]["fn"]: x for x in t}

    def test_pack_primed_task_still_mandates_source_and_warns(self):
        t = self._tasks(with_pack=True)
        fin = t["finalize"]
        self.assertTrue(fin.get("pack_primed"))
        p = fin["prompt"]
        self.assertIn("PRE-COMPUTED INTEL (PRIMING ONLY", p)
        self.assertIn("withdrawal replay guard", p)           # pack brief injected
        self.assertIn("READ THE REAL SOURCE YOURSELF", p)     # source read still mandatory
        self.assertIn("hallucinated", p)                       # pack-only warning present

    def test_fn_without_pack_not_primed(self):
        t = self._tasks(with_pack=True)
        prove = t["prove"]
        self.assertFalse(prove.get("pack_primed"))
        self.assertNotIn("PRE-COMPUTED INTEL", prove["prompt"])
        self.assertIn("READ THE REAL SOURCE YOURSELF", prove["prompt"])  # source read always required

    def test_flag_off_no_priming_anywhere(self):
        t = self._tasks(with_pack=False)
        for x in t.values():
            self.assertFalse(x.get("pack_primed"))
            self.assertNotIn("PRE-COMPUTED INTEL", x["prompt"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
