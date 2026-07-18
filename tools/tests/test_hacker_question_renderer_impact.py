"""Tests for the per-impact hunting-methodology wiring in
tools/hacker_question_renderer.py.

Covers the NET-NEW per-impact layer:
  - load_impact_playbooks (load + graceful-degrade)
  - classify_impact_target (the net-new language + contract_kind classifier)
  - render_impact_questions (union attach predicate: shape REQUIRED, language /
    contract_kind OPTIONAL; absent/empty optional filters never exclude)
  - render_hacker_questions(include_impact=...) additive merge

Mirrors test_hacker_question_renderer.py's loader style. Per Python 3.14, the
module is registered in sys.modules BEFORE exec_module so the module's own
`from __future__` / self-referential imports resolve.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "tools"
IMPACT_CORPUS_PATH = (
    REPO_ROOT / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml"
)

if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def _load_renderer():
    spec = importlib.util.spec_from_file_location(
        "hacker_question_renderer", str(TOOLS_DIR / "hacker_question_renderer.py")
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    # Python 3.14: register before exec so the module is importable by name
    # during its own execution.
    sys.modules["hacker_question_renderer"] = mod
    spec.loader.exec_module(mod)
    return mod


R = _load_renderer()


class TestLoadImpactPlaybooks(unittest.TestCase):
    """T1: load + graceful-degrade."""

    def test_bundled_corpus_present_and_nonempty(self):
        self.assertTrue(IMPACT_CORPUS_PATH.exists(), IMPACT_CORPUS_PATH)
        books = R.load_impact_playbooks(IMPACT_CORPUS_PATH)
        self.assertGreater(len(books), 0)

    def test_every_row_has_impact_id(self):
        for p in R.load_impact_playbooks(IMPACT_CORPUS_PATH):
            self.assertTrue(str(p.get("impact_id") or "").strip(), p)

    def test_missing_file_degrades_to_empty(self):
        out = R.load_impact_playbooks(Path("/nonexistent/impact_playbooks.yaml"))
        self.assertEqual(out, [])  # never raises

    def test_mined_set_ids_present(self):
        ids = {p["impact_id"] for p in R.load_impact_playbooks(IMPACT_CORPUS_PATH)}
        # A representative slice of the canonical mined set (halt + non-halt).
        for expected in (
            "direct-theft-funds",
            "share-supply-inflation",
            "unauthorized-mint",
            "chain-halt-shutdown",
            "reentrancy",
        ):
            self.assertIn(expected, ids)


class TestClassifyImpactTarget(unittest.TestCase):
    """T2: the net-new language + contract_kind classifier."""

    def test_go_consensus_infers_kind_and_shape(self):
        c = R.classify_impact_target(
            "finalizeBlock",
            "func finalizeBlock(ctx sdk.Context)",
            language="go",
            scope_text="cometbft consensus",
        )
        self.assertEqual(c["contract_kind"], "consensus")
        self.assertEqual(c["language"], "go")
        self.assertTrue(
            {"cosmos-msg-handler-fn", "state-machine-transition-fn"}
            & set(c["shape_classes"]),
            c["shape_classes"],
        )

    def test_explicit_contract_kind_overrides_inference(self):
        c = R.classify_impact_target(
            "swap", "function swap()", contract_kind="vault", scope_text="amm"
        )
        self.assertEqual(c["contract_kind"], "vault")

    def test_blank_when_no_signal(self):
        c = R.classify_impact_target("doThing", "func doThing()")
        self.assertEqual(c["contract_kind"], "")
        self.assertEqual(c["language"], "")

    def test_evm_vault_inferred_from_signature(self):
        c = R.classify_impact_target(
            "deposit", "function deposit() external returns (uint256 shares)",
            scope_text="ERC4626 vault convertToShares",
        )
        self.assertEqual(c["contract_kind"], "vault")


class TestImpactFilterAdmits(unittest.TestCase):
    """Unit of the optional-filter semantics (T5/T6 building block)."""

    def test_absent_filter_never_excludes(self):
        self.assertTrue(R._impact_filter_admits(None, "amm"))
        self.assertTrue(R._impact_filter_admits([], "amm"))

    def test_unknown_target_never_excluded(self):
        self.assertTrue(R._impact_filter_admits(["consensus"], ""))

    def test_mismatch_excludes(self):
        self.assertFalse(R._impact_filter_admits(["consensus", "abci-app"], "amm"))

    def test_match_admits(self):
        self.assertTrue(R._impact_filter_admits(["consensus", "abci-app"], "consensus"))


class TestRenderImpactQuestions(unittest.TestCase):
    def test_t3_positive_non_halt_render(self):
        # The generalization gate: a NON-halt impact (vault withdraw) renders.
        rows = R.render_impact_questions(
            "withdraw",
            "function withdraw(uint256 a) external",
            contract_kind="vault",
        )
        self.assertGreater(len(rows), 0)
        self.assertTrue(
            all(r["question_source"] == "impact-methodology" for r in rows)
        )
        ids = {r["impact_id"] for r in rows}
        self.assertIn("direct-theft-funds", ids)

    def test_t3_row_shape_well_formed(self):
        rows = R.render_impact_questions(
            "withdraw", "function withdraw(uint256) external", contract_kind="vault"
        )
        row = rows[0]
        for key in (
            "schema",
            "question",
            "question_source",
            "impact_id",
            "impact_severity_hint",
            "reasoning_axis",
            "proof_obligation",
            "kill_condition",
            "incident_anchor",
            "rubric_row_hint",
            "target_file",
            "mcp_context_pack_id",
        ):
            self.assertIn(key, row, key)
        self.assertEqual(row["schema"], R.HACKER_QUESTION_SCHEMA)
        self.assertTrue(row["question"].strip())
        self.assertTrue(row["proof_obligation"].strip())
        self.assertTrue(row["kill_condition"].strip())

    def test_t4_chain_halt_attaches_for_go_consensus(self):
        rows = R.render_impact_questions(
            "Finalize",
            "func Finalize(ctx sdk.Context) error",
            language="go",
            contract_kind="consensus",
        )
        ids = {r["impact_id"] for r in rows}
        self.assertIn("chain-halt-shutdown", ids)

    def test_t5_kind_filter_excludes_even_when_shape_intersects(self):
        # `finalize` classifies into state-machine-transition-fn which IS in
        # chain-halt's applies_to_shape_classes; the contract_kind=amm gate must
        # still exclude chain-halt (guards the "overfit-to-chain-halt" risk).
        rows = R.render_impact_questions(
            "finalize",
            "function finalize(uint256) external",
            language="solidity",
            contract_kind="amm",
        )
        ids = {r["impact_id"] for r in rows}
        self.assertNotIn("chain-halt-shutdown", ids)
        # ... but a DeFi impact still attaches on the same shape.
        self.assertIn("direct-theft-funds", ids)

    def test_t5b_same_shape_consensus_does_attach(self):
        rows = R.render_impact_questions(
            "finalize", "function finalize() external",
            language="go", contract_kind="consensus",
        )
        ids = {r["impact_id"] for r in rows}
        self.assertIn("chain-halt-shutdown", ids)

    def test_t6_empty_optional_filters_never_exclude(self):
        # A playbook with shape classes but NO applies_to_languages /
        # applies_to_contract_kinds attaches on shape alone, even with a blank
        # target language and kind.
        synth = [
            {
                "impact_id": "synthetic-shape-only",
                "title": "Synthetic shape-only",
                "applies_to_shape_classes": ["withdrawal-redemption-fn"],
                "hacker_questions": [{"q": "synthetic q?", "axis": "impact"}],
            }
        ]
        rows = R.render_impact_questions(
            "withdraw",
            "function withdraw(uint256) external",
            language="",
            contract_kind="",
            playbooks=synth,
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["impact_id"], "synthetic-shape-only")

    def test_no_shape_intersection_yields_nothing(self):
        synth = [
            {
                "impact_id": "needs-oracle-shape",
                "applies_to_shape_classes": ["oracle-read-fn"],
                "hacker_questions": [{"q": "q?"}],
            }
        ]
        rows = R.render_impact_questions(
            "withdraw", "function withdraw(uint256) external",
            contract_kind="vault", playbooks=synth,
        )
        self.assertEqual(rows, [])

    def test_max_questions_caps(self):
        rows = R.render_impact_questions(
            "withdraw", "function withdraw(uint256) external",
            contract_kind="vault", max_questions=3,
        )
        self.assertLessEqual(len(rows), 3)

    def test_empty_corpus_returns_empty(self):
        rows = R.render_impact_questions(
            "withdraw", "function withdraw(uint256) external",
            contract_kind="vault", playbooks=[],
        )
        self.assertEqual(rows, [])


class TestRenderHackerQuestionsMerge(unittest.TestCase):
    """T7: additive, non-breaking merge into render_hacker_questions."""

    def test_default_flags_include_impact_rows(self):
        rows = R.render_hacker_questions(
            ranked=[],
            function_name="withdraw",
            function_signature="function withdraw(uint256) external",
            contract_kind="vault",
        )
        srcs = {r["question_source"] for r in rows}
        self.assertIn("impact-methodology", srcs)

    def test_include_impact_false_drops_only_impact_rows(self):
        with_impact = R.render_hacker_questions(
            ranked=[],
            function_name="withdraw",
            function_signature="function withdraw(uint256) external",
            contract_kind="vault",
        )
        without = R.render_hacker_questions(
            ranked=[],
            function_name="withdraw",
            function_signature="function withdraw(uint256) external",
            contract_kind="vault",
            include_impact=False,
        )
        self.assertFalse(
            any(r["question_source"] == "impact-methodology" for r in without)
        )
        # Non-impact sources are a SUPERSET-preserving subset: every source in
        # `without` is also present in `with_impact` (impact rows are additive).
        self.assertTrue(
            {r["question_source"] for r in without}
            <= {r["question_source"] for r in with_impact}
        )

    def test_existing_callers_unaffected_economic_library_still_present(self):
        rows = R.render_hacker_questions(
            ranked=[],
            function_name="swap",
            function_signature="function swap(uint256) external",
        )
        # The pre-change sources must still render for a DeFi shape.
        srcs = {r["question_source"] for r in rows}
        self.assertIn("curated-library", srcs)


class TestGriefingDosNotCatchAll(unittest.TestCase):
    """Rule-2c fix: griefing-dos-blockstuffing (an L1-flavoured, R35-OOS-prone
    DoS class) must NOT attach to the catch-all external-state-mutating-fn shape,
    else it becomes the plurality impact on every plain mutator (initializers,
    setters) and mis-frames a Solidity DeFi audit as chain-halt/griefing.
    It MUST still attach to genuinely DoS-shaped functions (loops, withdrawals).
    """

    def _impact_ids(self, fn, sig="", language="solidity"):
        rows = R.render_impact_questions(fn, sig, language=language)
        return {r.get("impact_id") for r in rows if r.get("impact_id")}

    def test_catch_all_initializer_has_no_griefing(self):
        # __init_unchained classifies ONLY as external-state-mutating-fn.
        ids = self._impact_ids("__SSVNetwork_init_unchained")
        self.assertNotIn("griefing-dos-blockstuffing", ids)
        self.assertEqual(ids, set(), ids)  # honest absence, no misleading obligation

    def test_plain_setter_has_no_griefing(self):
        ids = self._impact_ids("setFeeRecipientAddress", "address r")
        self.assertNotIn("griefing-dos-blockstuffing", ids)

    def test_loop_batch_fn_still_gets_griefing(self):
        ids = self._impact_ids("bulkRegisterValidator", "bytes[] pk")
        self.assertIn("griefing-dos-blockstuffing", ids)

    def test_withdrawal_fn_still_gets_griefing_and_fund_theft(self):
        ids = self._impact_ids("withdraw", "uint256 amount")
        self.assertIn("griefing-dos-blockstuffing", ids)
        self.assertIn("direct-theft-funds", ids)  # value-mover keeps DeFi impacts

    def test_griefing_playbook_no_longer_lists_catch_all(self):
        for p in R.load_impact_playbooks(IMPACT_CORPUS_PATH):
            if p.get("impact_id") == "griefing-dos-blockstuffing":
                self.assertNotIn(
                    "external-state-mutating-fn",
                    p.get("applies_to_shape_classes") or [],
                )
                break
        else:
            self.fail("griefing-dos-blockstuffing playbook missing")

    def test_solidity_fn_never_gets_chain_halt_or_bc_impacts(self):
        # Language guard (rule-2c "NOT chain-halt"): a Solidity value-mover must
        # not carry go/rust blockchain-consensus impacts.
        ids = self._impact_ids("withdraw", "uint256 amount")
        for forbidden in (
            "chain-halt-shutdown",
            "bc-consensus-transient-failure",
            "bc-node-resource-exhaustion",
            "bc-direct-loss-of-funds",
        ):
            self.assertNotIn(forbidden, ids)


if __name__ == "__main__":
    unittest.main()
