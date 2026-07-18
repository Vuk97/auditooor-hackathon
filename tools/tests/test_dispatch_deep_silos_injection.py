# r36-rebuttal: lane silo-brief-injection-2026-06 registered in .auditooor/agent_pathspec.json
"""test_dispatch_deep_silos_injection.py - FIX 1 + FIX 2 wiring test.

Verifies tools/dispatch-agent-with-prebriefing.py's Section 15t Deep-Analysis
Silos surfaces the math-invariant spec (math_spec.json) and guard-probe-packet
(guard_probe_packets.jsonl) silos into a hunt-class brief.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "dispatch-agent-with-prebriefing.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("dispatch_agent_with_prebriefing", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestDeepSilosSection(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()

    def _ws(self, td):
        ws = Path(td)
        ad = ws / ".auditooor"
        ad.mkdir()
        mdir = ws / "math_invariants"
        mdir.mkdir()
        (mdir / "math_spec.json").write_text(json.dumps({
            "schema_version": "1.0",
            "contracts": {
                "Vault": {
                    "violations": [{"function": "burn", "law": "supply underflow path"}],
                    "candidates": [{"invariant": "totalAssets == sum(deposits)"}],
                }
            },
        }), encoding="utf-8")
        (ad / "guard_probe_packets.jsonl").write_text(json.dumps({
            "schema": "auditooor.guard_probe_packet.v1",
            "guard_id": "redeemGuard",
            "file_line": "src/Vault.sol:88",
            "guard_line": "require(shares <= balanceOf[msg.sender])",
            "invariant_hint": "does not check vault solvency before redeem",
            "invariant_context_incomplete": False,
        }) + "\n", encoding="utf-8")
        return ws

    def test_section_15t_injected_for_hunt_lane(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._ws(td)
            ctx = self.mod.build_deep_analysis_silos_context(
                workspace_path=ws, lane_type="hunt"
            )
            self.assertIsNotNone(ctx)
            lines = self.mod._format_deep_analysis_silos_section(ctx)
            blob = "\n".join(lines)
            self.assertIn("Section 15t - Deep-Analysis Silos", blob)
            # FIX 1
            self.assertIn("supply underflow path", blob)
            self.assertIn("totalAssets == sum(deposits)", blob)
            # FIX 2
            self.assertIn("redeemGuard", blob)
            self.assertIn("does not check vault solvency before redeem", blob)

    def test_none_for_non_hunt_lane(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._ws(td)
            ctx = self.mod.build_deep_analysis_silos_context(
                workspace_path=ws, lane_type="filing"
            )
            self.assertIsNone(ctx)
            self.assertEqual(self.mod._format_deep_analysis_silos_section(None), [])

    def test_none_when_no_silos(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()
            ctx = self.mod.build_deep_analysis_silos_context(
                workspace_path=ws, lane_type="hunt"
            )
            self.assertIsNone(ctx)


if __name__ == "__main__":
    unittest.main()
