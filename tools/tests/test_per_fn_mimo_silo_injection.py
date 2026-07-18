# r36-rebuttal: lane silo-brief-injection-2026-06 registered in .auditooor/agent_pathspec.json
"""test_per_fn_mimo_silo_injection.py - FIX 1 + FIX 2 wiring test.

Verifies tools/per-fn-mimo-batch-gen.py injects:
  - FIX 1: the MATH-INVARIANT SPEC block (from math_invariants/math_spec.json)
  - FIX 2: the GUARD PROBE PACKETS block (from .auditooor/guard_probe_packets.jsonl)
into the enriched per-fn MIMO task brief for the matching unit.
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


class TestSiloInjection(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()

    def _ws_with_silos(self, td: str):
        ws = Path(td)
        ad = ws / ".auditooor"
        ad.mkdir()
        src = ws / "src" / "Vault.sol"
        src.parent.mkdir(parents=True)
        src.write_text(
            "function mint(uint a) public {\n"
            "    totalSupply += a;\n"
            "}\n",
            encoding="utf-8",
        )
        # FIX 1 silo: math_spec.json (contract-keyed)
        mdir = ws / "math_invariants"
        mdir.mkdir()
        (mdir / "math_spec.json").write_text(json.dumps({
            "schema_version": "1.0",
            "tool": "math-invariant-miner.py",
            "contracts": {
                "Vault": {
                    "violations": [
                        {"function": "mint",
                         "law": "totalSupply increments but balanceOf does not"}
                    ],
                    "candidates": [
                        {"invariant": "sum(balanceOf) == totalSupply"}
                    ],
                }
            },
        }), encoding="utf-8")
        # FIX 2 silo: guard_probe_packets.jsonl (file_line-keyed)
        (ad / "guard_probe_packets.jsonl").write_text(json.dumps({
            "schema": "auditooor.guard_probe_packet.v1",
            "guard_id": "supplyCap",
            "file_line": "src/Vault.sol:1",
            "guard_line": "require(totalSupply + a <= CAP)",
            "invariant_hint": "does not check per-account mint limit",
            "invariant_context_incomplete": False,
        }) + "\n", encoding="utf-8")
        return ws, src

    def test_math_and_guard_probe_blocks_injected(self):
        with tempfile.TemporaryDirectory() as td:
            ws, src = self._ws_with_silos(td)

            math_idx = self.mod.load_math_spec_indexed(ws)
            probe_idx = self.mod.load_guard_probe_packets_indexed(ws)
            self.assertTrue(math_idx, "math_spec index empty")
            self.assertTrue(probe_idx, "guard_probe index empty")

            q = {
                "function": "mint",
                "file": str(src),
                "question_class": "accounting",
                "question": "Can mint break the supply conservation law?",
                "anchor_invariant": "supply-conservation",
                "rank": 1,
                "score": 9.0,
            }
            task = self.mod.build_enriched_task(
                0, q, ws, "testws", "DOCS", {}, {}, [],
                None, None, probe_idx, math_idx,
            )
            prompt = task["prompt"]
            # FIX 1 assertions
            self.assertIn("MATH-INVARIANT SPEC", prompt)
            self.assertIn("totalSupply increments but balanceOf does not", prompt)
            self.assertIn("sum(balanceOf) == totalSupply", prompt)
            # FIX 2 assertions
            self.assertIn("GUARD PROBE PACKETS", prompt)
            self.assertIn("supplyCap", prompt)
            self.assertIn("does not check per-account mint limit", prompt)

    def test_no_block_when_no_silos(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()
            src = ws / "Other.sol"
            src.write_text("function foo() public {}\n", encoding="utf-8")
            q = {
                "function": "foo", "file": str(src),
                "question_class": "generic", "question": "anything?",
                "anchor_invariant": "x", "rank": 1, "score": 1.0,
            }
            task = self.mod.build_enriched_task(
                0, q, ws, "testws", "DOCS", {}, {}, [], {}, {}, {}, {},
            )
            self.assertNotIn("MATH-INVARIANT SPEC", task["prompt"])
            self.assertNotIn("GUARD PROBE PACKETS", task["prompt"])


# r36-rebuttal: lane novelpanel-readback-2026-06 registered in .auditooor/agent_pathspec.json
class TestNovelPanelReadback(unittest.TestCase):
    """S8-novelpanel-readback: adversarial-differential-hypothesis +
    target-specific novel-invariant silos must be read back into the per-fn
    MIMO brief, gated per-file (mirror of the guard-deficiency readback)."""

    def setUp(self):
        self.mod = _load_module()

    def _ws_with_novel_silos(self, td: str):
        ws = Path(td)
        ad = ws / ".auditooor"
        ad.mkdir()
        src = ws / "src" / "Foo.sol"
        src.parent.mkdir(parents=True)
        src.write_text(
            "function harvest(uint a) public {\n"
            "    reward += a;\n"
            "}\n",
            encoding="utf-8",
        )
        # adversarial_hypothesis_top5.json (AHDH payload: top-level functions[])
        (ad / "adversarial_hypothesis_top5.json").write_text(json.dumps({
            "schema": "auditooor.adversarial_hypothesis_differential.v1",
            "functions": [
                {
                    "file_path": "src/Foo.sol",
                    "contract_name": "Foo",
                    "function_name": "harvest",
                    "hypotheses": [
                        {
                            "attack_class": "accounting-drift",
                            "violated_invariant": "reward MUST equal sum of accrued shares",
                            "manipulated_state": "reward accumulator",
                            "required_preconditions": ["attacker can call harvest twice"],
                            "source_ref": "src/Foo.sol:1",
                        }
                    ],
                }
            ],
        }), encoding="utf-8")
        # novel_vector_invariants.json (workspace-level; per_file -> jsonl)
        nv_jsonl = ad / "novel_vector_invariants_0.jsonl"
        nv_jsonl.write_text(json.dumps({
            "schema_version": "auditooor.novel_vector_invariant.v1",
            "target": "Foo",
            "function": "harvest",
            "family": "conservation",
            "invariant_class": "mutating-state",
            "statement": "harvest() MUST NOT increase reward beyond accrued entitlement",
            "assertion_expr": "reward_after <= reward_before + accrued",
        }) + "\n", encoding="utf-8")
        (ad / "novel_vector_invariants.json").write_text(json.dumps({
            "schema": "auditooor.novel_vector_invariants.v1",
            "per_file": [
                {"file": "src/Foo.sol", "lang": "solidity",
                 "derived": 1, "jsonl": str(nv_jsonl)}
            ],
        }), encoding="utf-8")
        return ws, src

    def test_adversarial_and_novel_vector_blocks_injected(self):
        with tempfile.TemporaryDirectory() as td:
            ws, src = self._ws_with_novel_silos(td)

            adv_idx = self.mod.load_adversarial_hypotheses_indexed(ws)
            nv_idx = self.mod.load_novel_vector_invariants_indexed(ws)
            self.assertTrue(adv_idx, "adversarial-hypothesis index empty")
            self.assertTrue(nv_idx, "novel-vector index empty")

            q = {
                "function": "harvest",
                "file": str(src),
                "question_class": "accounting",
                "question": "Can harvest break reward accounting?",
                "anchor_invariant": "reward-conservation",
                "rank": 1,
                "score": 8.0,
            }
            task = self.mod.build_enriched_task(
                0, q, ws, "testws", "DOCS", {}, {}, [],
                None, None, None, None, None, adv_idx, nv_idx,
            )
            prompt = task["prompt"]
            self.assertIn("ADVERSARIAL DIFFERENTIAL HYPOTHESES", prompt)
            self.assertIn("reward MUST equal sum of accrued shares", prompt)
            self.assertIn("TARGET-SPECIFIC NOVEL INVARIANTS", prompt)
            self.assertIn(
                "harvest() MUST NOT increase reward beyond accrued entitlement",
                prompt,
            )

    def test_blocks_gated_per_file(self):
        """A question anchored to an unrelated file must NOT pick up Foo.sol's
        adversarial/novel-vector blocks (per-file gating)."""
        with tempfile.TemporaryDirectory() as td:
            ws, _src = self._ws_with_novel_silos(td)
            adv_idx = self.mod.load_adversarial_hypotheses_indexed(ws)
            nv_idx = self.mod.load_novel_vector_invariants_indexed(ws)
            other = ws / "src" / "Bar.sol"
            other.write_text("function deposit() public {}\n", encoding="utf-8")
            q = {
                "function": "deposit",
                "file": str(other),
                "question_class": "generic",
                "question": "anything?",
                "anchor_invariant": "x",
                "rank": 1,
                "score": 1.0,
            }
            task = self.mod.build_enriched_task(
                0, q, ws, "testws", "DOCS", {}, {}, [],
                None, None, None, None, None, adv_idx, nv_idx,
            )
            prompt = task["prompt"]
            self.assertNotIn("ADVERSARIAL DIFFERENTIAL HYPOTHESES", prompt)
            self.assertNotIn("TARGET-SPECIFIC NOVEL INVARIANTS", prompt)

    def test_loaders_empty_when_absent(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()
            self.assertEqual(self.mod.load_adversarial_hypotheses_indexed(ws), {})
            self.assertEqual(self.mod.load_novel_vector_invariants_indexed(ws), {})


if __name__ == "__main__":
    unittest.main()
