"""F1 per-language UNION + batch-gen INV-grounding regression tests.

Covers the F1 (spec section F1) per-language additions in corpus-driven-hunt.py
and the E1.2 INV-grounding fold-in in mimo-harness-batch-gen.py:

  - a Go/Cosmos keeper module family-fits `consensus_state_machine` (the family
    that did not exist before F1; 397 'go' INVs could never family-fit the
    Solidity-shaped vocab);
  - a `.circom` file is now enumerated and its `template`/`function` symbols are
    surfaced as candidate functions (the ext was never in LANG_BY_EXT);
  - the Go view-class detector classifies a getter keeper fn (no store write) as
    a view and a store-writing setter as non-view;
  - a `corpus-hunt-fuel` exploit-queue row makes the generated mimo task carry
    `matched_invariant_id` (+ differential_test_idea) so the pipeline hunt is
    INV-grounded.

Run EXPLICITLY (never full-dir pytest, which hangs on collection):
  python3 -m pytest -q -p no:cacheprovider tools/tests/test_f1_perlang_and_batch.py
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools"))


def _load_tool(mod_name, filename):
    """Load a sibling tools/*.py module by file path (hyphenated names cannot be
    imported normally). Mirrors the loader other tools/tests use."""
    spec = importlib.util.spec_from_file_location(
        mod_name, str(REPO / "tools" / filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


cdh = _load_tool("_cdh_f1_test", "corpus-driven-hunt.py")
mhbg = _load_tool("_mhbg_f1_test", "mimo-harness-batch-gen.py")


class GoCosmosFamilyTest(unittest.TestCase):
    def test_keeper_module_fits_consensus_state_machine(self):
        d = tempfile.mkdtemp()
        src = Path(d) / "x" / "foo" / "keeper"
        src.mkdir(parents=True)
        (src / "keeper.go").write_text(
            "package keeper\n"
            "func (k Keeper) EndBlock(ctx sdk.Context) {\n"
            "  store := ctx.KVStore(k.storeKey)\n"
            "  for _, v := range k.GetValidators(ctx) { store.Set(v) }\n"
            "}\n"
            "func (k msgServer) ProcessProposal(ctx sdk.Context) error {\n"
            "  return k.ValidateBasic()\n"
            "}\n"
            "func (k Keeper) GetValidators(ctx sdk.Context) []byte { return nil }\n",
            encoding="utf-8")
        tm = cdh.build_target_model(Path(d), max_functions=0)
        self.assertIn("go", tm.languages)
        # The new family is present and family-fits (the whole point of F1).
        self.assertIn("consensus_state_machine", tm.families_active)
        self.assertEqual(cdh._family_fit("consensus_state_machine",
                                         tm.families_active), 1.0)
        # The keeper functions were enumerated.
        names = {f.name for f in tm.functions}
        self.assertIn("EndBlock", names)
        self.assertIn("ProcessProposal", names)

    def test_consensus_family_registered_in_table(self):
        self.assertIn("consensus_state_machine", cdh.FAMILY_BY_NAME)
        self.assertIn("account_model", cdh.FAMILY_BY_NAME)
        self.assertIn("move_resource_model", cdh.FAMILY_BY_NAME)


class GoViewDetectTest(unittest.TestCase):
    def test_getter_with_context_no_store_write_is_view(self):
        win = "(ctx sdk.Context, k string) string { return k }"
        self.assertTrue(cdh._detect_view("go", win, "GetFoo"))

    def test_setter_writing_store_is_not_view(self):
        win = "(ctx sdk.Context, k string) { store.Set(k) }"
        self.assertFalse(cdh._detect_view("go", win, "SetFoo"))

    def test_getter_name_but_store_delete_is_not_view(self):
        win = "(ctx sdk.Context) { store.Delete(x) }"
        self.assertFalse(cdh._detect_view("go", win, "GetBar"))

    def test_non_context_getter_is_not_view(self):
        # name matches the getter pattern but the fn does not take sdk.Context.
        win = "(x int) int { return x }"
        self.assertFalse(cdh._detect_view("go", win, "GetThing"))


class CircomEnumerationTest(unittest.TestCase):
    def test_circom_file_enumerates_template_fn(self):
        d = tempfile.mkdtemp()
        (Path(d) / "c.circom").write_text(
            "pragma circom 2.0.0;\n"
            "template Multiplier() { signal input a; signal output c; c <== a*a; }\n"
            "function helper(x) { return x+1; }\n",
            encoding="utf-8")
        tm = cdh.build_target_model(Path(d), max_functions=0)
        self.assertIn("circom", tm.languages)
        names = {f.name for f in tm.functions}
        self.assertIn("Multiplier", names)
        self.assertIn("helper", names)

    def test_lang_by_ext_has_circuit_exts(self):
        self.assertEqual(cdh.LANG_BY_EXT.get(".circom"), "circom")
        self.assertEqual(cdh.LANG_BY_EXT.get(".nr"), "noir")
        self.assertEqual(cdh.LANG_BY_EXT.get(".zok"), "zokrates")

    def test_noir_fn_enumerated(self):
        d = tempfile.mkdtemp()
        (Path(d) / "main.nr").write_text(
            "fn main(x: Field) -> pub Field { x + 1 }\n",
            encoding="utf-8")
        tm = cdh.build_target_model(Path(d), max_functions=0)
        self.assertIn("noir", tm.languages)
        self.assertIn("main", {f.name for f in tm.functions})


class AccountingTokenUnionTest(unittest.TestCase):
    def test_cosmos_bank_tokens_fit_accounting(self):
        d = tempfile.mkdtemp()
        (Path(d) / "bank.go").write_text(
            "package keeper\n"
            "func (k Keeper) Move(ctx sdk.Context) { k.bank.SendCoins(ctx, a, b, sdk.Coins{}) }\n",
            encoding="utf-8")
        tm = cdh.build_target_model(Path(d), max_functions=0)
        self.assertIn("accounting_conservation", tm.families_active)

    def test_solana_value_flow_tokens_fit_accounting(self):
        d = tempfile.mkdtemp()
        (Path(d) / "lib.rs").write_text(
            "pub fn pay(ctx: Context) -> Result<()> {\n"
            "  **acc.try_borrow_mut_lamports()? -= amount;\n"
            "  invoke_signed(&ix, accs, seeds)?;\n"
            "  Ok(())\n}\n",
            encoding="utf-8")
        tm = cdh.build_target_model(Path(d), max_functions=0)
        self.assertIn("accounting_conservation", tm.families_active)


class MimoBatchInvGroundingTest(unittest.TestCase):
    def _ws_with_fuel(self, rows):
        d = tempfile.mkdtemp()
        ad = Path(d) / ".auditooor"
        ad.mkdir(parents=True)
        (ad / "exploit_queue.json").write_text(json.dumps(rows), encoding="utf-8")
        return d

    def test_fuel_row_grounds_task(self):
        rows = [
            {"source": "corpus-hunt-fuel",
             "broken_invariant_ids": ["INV-CON-004"],
             "negative_control": "cap=X vs cap=Y differential",
             "contract": "Vault.sol", "function": "redeem",
             "priority_score": 0.9},
            {"source": "source-mined",
             "broken_invariant_ids": ["INV-OTHER"],
             "contract": "Other.sol", "function": "foo"},
        ]
        d = self._ws_with_fuel(rows)
        idx = mhbg.load_corpus_hunt_fuel_index(d)
        # only the corpus-hunt-fuel row is indexed.
        self.assertEqual(idx["fallback"]["matched_invariant_id"], "INV-CON-004")
        self.assertIn("vault.sol.redeem", idx["by_unit"])
        q = {"question_id": "Q1", "question_text": "check redeem conservation",
             "attack_class": "accounting_conservation",
             "target_contract_patterns": ["Vault.sol"],
             "target_function_patterns": ["redeem"]}
        g = mhbg.resolve_inv_grounding(q, idx)
        self.assertEqual(g["matched_invariant_id"], "INV-CON-004")
        task = mhbg.build_task(0, "ws", d, q, "ctx", "taskctx", {}, None, g)
        self.assertEqual(task["matched_invariant_id"], "INV-CON-004")
        self.assertEqual(task["differential_test_idea"], "cap=X vs cap=Y differential")
        self.assertIn("INV-CON-004", task["prompt"])
        self.assertIn("cap=X vs cap=Y differential", task["prompt"])

    def test_fallback_when_no_pattern_match(self):
        rows = [{"source": "corpus-hunt-fuel",
                 "broken_invariant_ids": ["INV-AUTH-001"],
                 "negative_control": "", "contract": "A.sol",
                 "function": "f", "priority_score": 0.5}]
        d = self._ws_with_fuel(rows)
        idx = mhbg.load_corpus_hunt_fuel_index(d)
        g = mhbg.resolve_inv_grounding({"question_id": "Q"}, idx)
        self.assertEqual(g["matched_invariant_id"], "INV-AUTH-001")

    def test_no_fuel_rows_is_noop(self):
        d = self._ws_with_fuel([{"source": "source-mined",
                                 "broken_invariant_ids": ["X"]}])
        idx = mhbg.load_corpus_hunt_fuel_index(d)
        self.assertEqual(idx["fallback"], {})
        g = mhbg.resolve_inv_grounding({"question_id": "Q"}, idx)
        self.assertEqual(g, {})
        task = mhbg.build_task(0, "ws", d, {"question_id": "Q",
                              "question_text": "t", "attack_class": "x"},
                              "ctx", "tc", {}, None, g)
        self.assertEqual(task["matched_invariant_id"], "")
        self.assertNotIn("INV-GROUNDING", task["prompt"])

    def test_missing_queue_file_is_noop(self):
        d = tempfile.mkdtemp()
        idx = mhbg.load_corpus_hunt_fuel_index(d)
        self.assertEqual(idx["fallback"], {})


if __name__ == "__main__":
    unittest.main()
