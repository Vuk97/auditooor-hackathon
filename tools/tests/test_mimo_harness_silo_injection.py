# r36-rebuttal: lane silo-brief-injection-2026-06 registered in .auditooor/agent_pathspec.json
"""test_mimo_harness_silo_injection.py - FIX 1 + FIX 2 wiring test.

Verifies tools/mimo-harness-batch-gen.py's build_deep_silo_block surfaces the
workspace-level math-invariant spec (math_spec.json) and guard-probe-packet
(guard_probe_packets.jsonl) silos into the harness-mode brief context.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "mimo-harness-batch-gen.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("mimo_harness_batch_gen", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestHarnessSiloInjection(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()

    def test_deep_silo_block_surfaces_both(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            ad = ws / ".auditooor"
            ad.mkdir()
            mdir = ws / "math_invariants"
            mdir.mkdir()
            (mdir / "math_spec.json").write_text(json.dumps({
                "schema_version": "1.0",
                "contracts": {
                    "Pool": {
                        "violations": [
                            {"function": "swap", "law": "k=x*y not preserved"}
                        ],
                        "candidates": [{"invariant": "reserve0*reserve1 >= kLast"}],
                    }
                },
            }), encoding="utf-8")
            (ad / "guard_probe_packets.jsonl").write_text(json.dumps({
                "schema": "auditooor.guard_probe_packet.v1",
                "guard_id": "slippageGuard",
                "file_line": "src/Pool.sol:42",
                "invariant_hint": "does not bound output below minOut",
            }) + "\n", encoding="utf-8")

            block = self.mod.build_deep_silo_block(ws)
            self.assertIn("MATH-INVARIANT SPEC", block)
            self.assertIn("k=x*y not preserved", block)
            self.assertIn("reserve0*reserve1 >= kLast", block)
            self.assertIn("GUARD PROBE PACKETS", block)
            self.assertIn("slippageGuard", block)
            self.assertIn("does not bound output below minOut", block)

    def test_empty_when_no_silos(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()
            self.assertEqual(self.mod.build_deep_silo_block(ws), "")


if __name__ == "__main__":
    unittest.main()
