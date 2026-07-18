"""Tests for tools/hacker_question_renderer.py - W5-F1 + W5-F3.

W5-F1 covers: library load + integrity, function-shape classification, library
question rendering, and integration into render_hacker_questions.

W5-F3 covers: economic-attack-primitive corpus load + integrity, shape-class
intersection rendering, economic-primitive row well-formedness, and integration
into render_hacker_questions.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "tools"
LIBRARY_PATH = REPO_ROOT / "audit" / "corpus_tags" / "hacker_question_library.yaml"
ECONOMIC_PRIMITIVES_PATH = (
    REPO_ROOT / "audit" / "corpus_tags" / "economic_attack_primitives.yaml"
)

if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def _load_renderer():
    spec = importlib.util.spec_from_file_location(
        "hacker_question_renderer", str(TOOLS_DIR / "hacker_question_renderer.py")
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


R = _load_renderer()


class TestQuestionLibraryIntegrity(unittest.TestCase):
    def test_library_file_exists(self):
        self.assertTrue(LIBRARY_PATH.is_file(), f"missing {LIBRARY_PATH}")

    def test_library_loads(self):
        lib = R.load_question_library()
        self.assertGreater(len(lib), 0, "library loaded empty")

    def test_library_has_target_coverage(self):
        lib = R.load_question_library()
        # Roadmap target: 120+ questions, broad function-shape coverage.
        total = sum(len(sc.get("questions", [])) for sc in lib.values())
        self.assertGreaterEqual(total, 120, f"only {total} questions")
        self.assertGreaterEqual(len(lib), 12, f"only {len(lib)} shape classes")

    def test_every_question_well_formed(self):
        lib = R.load_question_library()
        for class_id, shape_class in lib.items():
            qs = shape_class.get("questions", [])
            self.assertGreater(len(qs), 0, f"{class_id} has no questions")
            for entry in qs:
                self.assertTrue(str(entry.get("q") or "").strip(),
                                f"{class_id} has empty question text")
                self.assertTrue(str(entry.get("axis") or "").strip(),
                                f"{class_id} question missing axis")
                self.assertTrue(str(entry.get("why") or "").strip(),
                                f"{class_id} question missing why")

    def test_questions_are_not_taxonomy_labels(self):
        # A real probing question is a sentence ending in "?"; a label is not.
        lib = R.load_question_library()
        for class_id, shape_class in lib.items():
            for entry in shape_class.get("questions", []):
                text = str(entry.get("q") or "")
                self.assertTrue(text.rstrip().endswith("?"),
                                f"{class_id}: not phrased as a question: {text}")
                self.assertGreater(len(text.split()), 8,
                                   f"{class_id}: too short to be a real question")

    def test_no_em_dashes(self):
        raw = LIBRARY_PATH.read_text(encoding="utf-8")
        self.assertNotIn("—", raw, "em-dash in library")
        self.assertNotIn("–", raw, "en-dash in library")


class TestClassifyFunctionShape(unittest.TestCase):
    def test_withdrawal_classifies(self):
        classes = R.classify_function_shape("withdrawCollateral", "")
        self.assertIn("withdrawal-redemption-fn", classes)

    def test_setter_classifies(self):
        classes = R.classify_function_shape("setOracle", "function setOracle(address o) external onlyOwner")
        self.assertIn("access-controlled-setter", classes)

    def test_oracle_read_classifies(self):
        classes = R.classify_function_shape("getPrice", "function getPrice() external view returns (uint256)")
        self.assertIn("oracle-read-fn", classes)

    def test_signature_path_classifies(self):
        classes = R.classify_function_shape("permit", "function permit(...) external")
        self.assertIn("signature-nonce-fn", classes)

    def test_initializer_classifies(self):
        classes = R.classify_function_shape("initialize", "")
        self.assertIn("upgrade-init-fn", classes)

    def test_cosmos_msg_handler_classifies(self):
        classes = R.classify_function_shape(
            "MsgPlaceOrder", "func (k Keeper) MsgPlaceOrder(ctx sdk.Context, msg *types.MsgPlaceOrder) error")
        self.assertIn("cosmos-msg-handler-fn", classes)

    def test_unknown_mutator_falls_back(self):
        classes = R.classify_function_shape("doSomethingObscure", "")
        self.assertEqual(classes, ["external-state-mutating-fn"])

    def test_view_falls_back_to_view_class(self):
        classes = R.classify_function_shape("isActive", "function isActive() public view returns (bool)")
        self.assertIn("view-getter-fn", classes)

    def test_always_returns_at_least_one_class(self):
        for name in ("", "x", "frobnicate", "withdraw", "transfer"):
            self.assertGreaterEqual(len(R.classify_function_shape(name, "")), 1)


class TestRenderLibraryQuestions(unittest.TestCase):
    def test_renders_curated_questions(self):
        rows = R.render_library_questions("withdraw", "")
        self.assertGreater(len(rows), 0)
        for row in rows:
            self.assertEqual(row["question_source"], "curated-library")
            self.assertTrue(row["question"].endswith("?"))
            self.assertTrue(row["shape_class"])
            self.assertTrue(row["reasoning_axis"])

    def test_max_questions_caps_output(self):
        rows = R.render_library_questions("withdraw", "", max_questions=3)
        self.assertLessEqual(len(rows), 3)

    def test_no_duplicate_question_text(self):
        rows = R.render_library_questions(
            "withdrawAndTransfer", "function withdrawAndTransfer(...) external")
        texts = [r["question"] for r in rows]
        self.assertEqual(len(texts), len(set(texts)), "duplicate question rendered")


class TestRenderHackerQuestionsIntegration(unittest.TestCase):
    def test_library_questions_appended(self):
        ranked = [{"attack_class": "reentrancy", "evidence": [{"record_id": "r1"}]}]
        rows = R.render_hacker_questions(
            ranked=ranked, function_name="withdraw",
            function_signature="function withdraw() external")
        sources = {r.get("question_source") for r in rows}
        self.assertIn("corpus-derived", sources)
        self.assertIn("curated-library", sources)

    def test_corpus_derived_still_present(self):
        ranked = [{"attack_class": "oracle-manipulation", "evidence": [{"record_id": "r2"}]}]
        rows = R.render_hacker_questions(ranked=ranked, function_name="getPrice")
        corpus = [r for r in rows if r.get("question_source") == "corpus-derived"]
        self.assertEqual(len(corpus), 1)
        self.assertEqual(corpus[0]["attack_class"], "oracle-manipulation")

    def test_include_library_false_disables(self):
        ranked = [{"attack_class": "reentrancy", "evidence": [{"record_id": "r3"}]}]
        rows = R.render_hacker_questions(
            ranked=ranked, function_name="withdraw", include_library=False)
        sources = {r.get("question_source") for r in rows}
        self.assertNotIn("curated-library", sources)

    def test_empty_ranked_still_yields_library_questions(self):
        # include_impact=False reproduces the pre-impact-wiring output exactly
        # (per WIRING_SPEC A4/T7): library-only for a pure access-controlled
        # setter. The default-on impact layer is exercised separately in
        # test_hacker_question_renderer_impact.py.
        rows = R.render_hacker_questions(
            ranked=[], function_name="setAdmin", include_impact=False)
        self.assertGreater(len(rows), 0)
        self.assertTrue(all(r.get("question_source") == "curated-library" for r in rows))
        for row in rows:
            self.assertEqual(row["proof_gate"], "source_confirmed")
            self.assertIn("Advisory hacker question only", row["claim_boundary"])
            self.assertIn("real source path", row["proof_obligation"])
            self.assertIn("Kill if", row["kill_condition"])


class TestEconomicPrimitiveCorpusIntegrity(unittest.TestCase):
    """W5-F3: economic-attack-primitive corpus load + integrity."""

    def test_corpus_file_exists(self):
        self.assertTrue(ECONOMIC_PRIMITIVES_PATH.is_file(),
                        f"missing {ECONOMIC_PRIMITIVES_PATH}")

    def test_corpus_loads(self):
        prims = R.load_economic_primitives()
        self.assertGreater(len(prims), 0, "economic-primitive corpus loaded empty")

    def test_corpus_has_target_coverage(self):
        # Roadmap H5-3 lists 9 named primitives; require at least that many.
        prims = R.load_economic_primitives()
        self.assertGreaterEqual(len(prims), 9, f"only {len(prims)} primitives")

    def test_every_primitive_well_formed(self):
        prims = R.load_economic_primitives()
        ids = set()
        for prim in prims:
            pid = str(prim.get("id") or "").strip()
            self.assertTrue(pid, "primitive missing id")
            self.assertNotIn(pid, ids, f"duplicate primitive id {pid}")
            ids.add(pid)
            for field in ("title", "category", "mechanism",
                          "profit_source", "incident_anchor"):
                self.assertTrue(prim.get(field),
                                f"{pid} missing {field}")
            applies = prim.get("applies_to_shape_classes")
            self.assertIsInstance(applies, list)
            self.assertGreater(len(applies), 0, f"{pid} applies to no shape class")
            self.assertGreater(len(prim.get("preconditions") or []), 0,
                               f"{pid} has no preconditions")
            self.assertGreater(len(prim.get("detect_signals") or []), 0,
                               f"{pid} has no detect_signals")
            qs = prim.get("questions") or []
            self.assertGreater(len(qs), 0, f"{pid} has no questions")
            for entry in qs:
                text = str(entry.get("q") or "")
                self.assertTrue(text.rstrip().endswith("?"),
                                f"{pid}: not a question: {text}")
                self.assertGreater(len(text.split()), 8,
                                   f"{pid}: question too short")
                self.assertEqual(entry.get("axis"), "economic",
                                 f"{pid}: economic primitive axis must be economic")
                self.assertTrue(str(entry.get("why") or "").strip(),
                                f"{pid}: question missing why")

    def test_applies_to_classes_exist_in_library(self):
        # Every applies_to_shape_classes id must be a real library shape class.
        lib_ids = set(R.load_question_library().keys())
        for prim in R.load_economic_primitives():
            for cid in prim.get("applies_to_shape_classes") or []:
                self.assertIn(str(cid), lib_ids,
                              f"{prim.get('id')} references unknown shape class {cid}")

    def test_no_em_dashes(self):
        raw = ECONOMIC_PRIMITIVES_PATH.read_text(encoding="utf-8")
        self.assertNotIn("—", raw, "em-dash in economic-primitive corpus")
        self.assertNotIn("–", raw, "en-dash in economic-primitive corpus")

    def test_named_primitives_present(self):
        ids = {p.get("id") for p in R.load_economic_primitives()}
        for expected in ("donation-inflation-attack", "sandwich-mev",
                         "oracle-manipulation-arbitrage", "fee-rounding-skim",
                         "liquidation-cascade", "jit-liquidity",
                         "vote-bribery-flashloan-governance",
                         "interest-rate-manipulation", "share-price-dilution"):
            self.assertIn(expected, ids, f"missing primitive {expected}")


class TestRenderEconomicPrimitiveQuestions(unittest.TestCase):
    """W5-F3: economic-primitive question rendering."""

    def test_vault_math_fn_gets_economic_questions(self):
        rows = R.render_economic_primitive_questions(
            "convertToShares",
            "function convertToShares(uint256 assets) public view returns (uint256)")
        self.assertGreater(len(rows), 0, "vault math fn got no economic questions")
        for row in rows:
            self.assertEqual(row["question_source"], "economic-primitive")
            self.assertEqual(row["reasoning_axis"], "economic")
            self.assertTrue(row["question"].endswith("?"))
            self.assertTrue(row["economic_primitive"])
            self.assertTrue(row["profit_source"])
            self.assertTrue(row["incident_anchor"])

    def test_donation_primitive_reaches_accounting_fn(self):
        rows = R.render_economic_primitive_questions("previewDeposit", "")
        prims = {r["economic_primitive"] for r in rows}
        # previewDeposit classifies accounting-math-fn -> donation-inflation applies.
        self.assertIn("donation-inflation-attack", prims)

    def test_oracle_fn_gets_oracle_primitive(self):
        rows = R.render_economic_primitive_questions(
            "getPrice", "function getPrice() external view returns (uint256)")
        prims = {r["economic_primitive"] for r in rows}
        self.assertIn("oracle-manipulation-arbitrage", prims)

    def test_liquidation_fn_gets_cascade_primitive(self):
        rows = R.render_economic_primitive_questions(
            "liquidate", "function liquidate(address borrower) external")
        prims = {r["economic_primitive"] for r in rows}
        self.assertIn("liquidation-cascade", prims)

    def test_governance_fn_gets_vote_bribery_primitive(self):
        rows = R.render_economic_primitive_questions(
            "castVote", "function castVote(uint256 proposalId, uint8 support) external")
        prims = {r["economic_primitive"] for r in rows}
        self.assertIn("vote-bribery-flashloan-governance", prims)

    def test_non_defi_fn_gets_no_economic_questions(self):
        # A privileged setter with no DeFi shape should not pull economic
        # primitives (none of the primitives apply to access-controlled-setter).
        rows = R.render_economic_primitive_questions(
            "setAdmin", "function setAdmin(address a) external onlyOwner")
        self.assertEqual(rows, [])

    def test_max_questions_caps_output(self):
        rows = R.render_economic_primitive_questions(
            "convertToShares", "", max_questions=4)
        self.assertLessEqual(len(rows), 4)

    def test_no_duplicate_question_text(self):
        rows = R.render_economic_primitive_questions(
            "depositAndHarvest",
            "function depositAndHarvest(uint256 assets) external")
        texts = [r["question"] for r in rows]
        self.assertEqual(len(texts), len(set(texts)), "duplicate economic question")


class TestRenderHackerQuestionsEconomicIntegration(unittest.TestCase):
    """W5-F3: economic-primitive integration into render_hacker_questions."""

    def test_economic_questions_appended_for_defi_fn(self):
        ranked = [{"attack_class": "oracle-manipulation",
                   "evidence": [{"record_id": "r1"}]}]
        rows = R.render_hacker_questions(
            ranked=ranked, function_name="getPrice",
            function_signature="function getPrice() external view returns (uint256)")
        sources = {r.get("question_source") for r in rows}
        self.assertIn("corpus-derived", sources)
        self.assertIn("curated-library", sources)
        self.assertIn("economic-primitive", sources)

    def test_include_economic_false_disables(self):
        ranked = [{"attack_class": "rounding", "evidence": [{"record_id": "r2"}]}]
        rows = R.render_hacker_questions(
            ranked=ranked, function_name="deposit",
            function_signature="function deposit(uint256 a) external",
            include_economic=False)
        sources = {r.get("question_source") for r in rows}
        self.assertNotIn("economic-primitive", sources)

    def test_non_defi_fn_yields_no_economic_questions(self):
        ranked = [{"attack_class": "admin-bypass", "evidence": [{"record_id": "r3"}]}]
        rows = R.render_hacker_questions(
            ranked=ranked, function_name="setAdmin",
            function_signature="function setAdmin(address a) external onlyOwner")
        econ = [r for r in rows if r.get("question_source") == "economic-primitive"]
        self.assertEqual(econ, [])

    def test_empty_ranked_still_yields_economic_for_defi_fn(self):
        rows = R.render_hacker_questions(
            ranked=[], function_name="convertToShares",
            function_signature="function convertToShares(uint256 a) public view")
        econ = [r for r in rows if r.get("question_source") == "economic-primitive"]
        self.assertGreater(len(econ), 0)
        self.assertTrue(all(row["proof_gate"] == "source_confirmed" for row in econ))
        self.assertTrue(all("economic preconditions" in row["proof_obligation"] for row in econ))
        self.assertTrue(all("profit source" in row["kill_condition"] for row in econ))

    def test_max_economic_questions_caps(self):
        rows = R.render_hacker_questions(
            ranked=[], function_name="convertToShares",
            function_signature="function convertToShares(uint256 a) public view",
            include_library=False, max_economic_questions=3)
        econ = [r for r in rows if r.get("question_source") == "economic-primitive"]
        self.assertLessEqual(len(econ), 3)


if __name__ == "__main__":
    unittest.main()
