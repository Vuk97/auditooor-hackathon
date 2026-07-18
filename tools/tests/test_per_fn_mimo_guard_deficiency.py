"""test_per_fn_mimo_guard_deficiency.py - FIX 2 wiring test.

Verifies that tools/per-fn-mimo-batch-gen.py injects a GUARD NEGATIVE-SPACE +
SIBLING-PATH ASYMMETRY context block into the enriched task brief for a unit
whose file matches an entry in negative_space_gaps.jsonl /
sibling_guard_asymmetries.jsonl.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "per-fn-mimo-batch-gen.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("per_fn_mimo_batch_gen", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestGuardDeficiencyInjection(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()

    def test_negative_space_block_injected(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            ad = ws / ".auditooor"
            ad.mkdir()
            src = ws / "src" / "Vault.sol"
            src.parent.mkdir(parents=True)
            src.write_text(
                "function withdraw(uint a) public {\n"
                "    balance -= a;\n"
                "}\n",
                encoding="utf-8",
            )
            (ad / "negative_space_gaps.jsonl").write_text(
                json.dumps({
                    "schema": "auditooor.negative_space_gap.v1",
                    "file_line": "src/Vault.sol:1",
                    "guard_id": "onlyOwner",
                    "kind": "access-control",
                    "invariant_hint": "withdraw must check caller is owner",
                    "gap_found": True,
                }) + "\n",
                encoding="utf-8",
            )
            (ad / "sibling_guard_asymmetries.jsonl").write_text(
                json.dumps({
                    "schema": "auditooor.sibling_path_guard_diff.v1",
                    "pair": "deposit/withdraw",
                    "path_a": {"file": "src/Vault.sol", "line": 10, "name": "deposit"},
                    "path_b": {"file": "src/Vault.sol", "line": 1, "name": "withdraw"},
                    "guard_on_a_missing_on_b": ["nonReentrant"],
                    "shared_invariant_hint": "both arms must be reentrancy-guarded",
                    "verdict": "asymmetry-candidate",
                }) + "\n",
                encoding="utf-8",
            )

            negspace_idx = self.mod.load_guard_negative_space_indexed(ws)
            asym_idx = self.mod.load_sibling_asymmetries_indexed(ws)
            self.assertTrue(negspace_idx, "negative_space index empty")
            self.assertTrue(asym_idx, "asymmetry index empty")

            q = {
                "function": "withdraw",
                "file": str(src),
                "question_class": "access-control",
                "question": "Can withdraw be called by a non-owner?",
                "anchor_invariant": "owner-only-withdraw",
                "rank": 1,
                "score": 9.0,
            }
            task = self.mod.build_enriched_task(
                0, q, ws, "testws", "DOCS", {}, {}, [],
                negspace_idx, asym_idx,
            )
            prompt = task["prompt"]
            self.assertIn("GUARD NEGATIVE-SPACE", prompt)
            self.assertIn("withdraw must check caller is owner", prompt)
            self.assertIn("SIBLING-PATH ASYMMETRY", prompt)
            self.assertIn("nonReentrant", prompt)

    def test_no_block_when_no_match(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()
            src = ws / "Other.sol"
            src.write_text("function foo() public {}\n", encoding="utf-8")
            q = {
                "function": "foo",
                "file": str(src),
                "question_class": "generic",
                "question": "anything?",
                "anchor_invariant": "x",
                "rank": 1, "score": 1.0,
            }
            task = self.mod.build_enriched_task(
                0, q, ws, "testws", "DOCS", {}, {}, [], {}, {},
            )
            self.assertNotIn("GUARD NEGATIVE-SPACE", task["prompt"])


if __name__ == "__main__":
    unittest.main()
