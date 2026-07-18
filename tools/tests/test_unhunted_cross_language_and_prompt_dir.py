#!/usr/bin/env python3
"""Guards for the unhunted-surface-followthrough-gate cross-language +
prompt-input fixes (NUVA close-out, Go/Cosmos serving-join).

Three generic defects the gate had, each surfaced on the NUVA Go/Cosmos target
whose function_coverage_completeness.json tracks 100 Go units alongside the
Solidity ones:

  1. `_UNIT_TARGET_RE` was `.sol`-only, so a `<file>.go::<fn>` surface parsed to
     None and was kept CONSERVATIVELY instead of being cross-credited against -
     and dropped by - the authoritative Go value-moving fc ledger. Every
     non-value-moving Go infra surface (module.go::ConsensusVersion,
     errors.go::Unwrap, keeper.go::getLogger) sat abandoned forever.

  2. A bare mining-OBLIGATION bookkeeping row
     (`[obligation:<hash>] <class>: mined_findings_hunter_bridge`) carries NO
     code surface, yet was kept conservatively (no `.sol`, no `@ fn`).

  3. `_candidate_artifacts` scanned `.auditooor/dispatch_briefs/` - agent PROMPT
     briefs that quote the surface/skeleton vocabulary as TEMPLATE text - and
     re-flagged the prompt itself as an abandoned surface (self-scan FP).

All three fixes are fail-safe: no fc ledger / no obligation tag / a real code
surface all leave the prior conservative behavior intact.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "ug", str(_TOOLS / "unhunted-surface-followthrough-gate.py"))
ug = importlib.util.module_from_spec(_spec)
sys.modules["ug"] = ug
_spec.loader.exec_module(ug)


class TestMultiLanguageUnitTarget(unittest.TestCase):
    def test_go_unit_target_parses(self):
        # `<file>.go::<fn>` now resolves to a (basename, fn) unit key.
        self.assertEqual(
            ug._parse_unit_target("unhunted-surface target: module.go::ConsensusVersion"),
            ("module.go", "consensusversion"),
        )

    def test_rust_and_move_unit_targets_parse(self):
        self.assertEqual(
            ug._parse_unit_target("unhunted-surface target: keeper.rs::PayInterest"),
            ("keeper.rs", "payinterest"),
        )
        self.assertEqual(
            ug._parse_unit_target("x vault.move::withdraw"),
            ("vault.move", "withdraw"),
        )

    def test_sol_target_unchanged(self):
        # Regression: the Solidity behavior is byte-identical.
        self.assertEqual(
            ug._parse_unit_target("Vault.sol::deposit"),
            ("vault.sol", "deposit"),
        )

    def test_unknown_extension_stays_none(self):
        # Fail-safe: an unrecognised extension yields None (kept conservatively),
        # never a spurious drop.
        self.assertIsNone(ug._parse_unit_target("unhunted-surface target: notes.txt::foo"))

    def test_go_infra_surface_dropped_out_of_universe(self):
        # A Go infra surface NOT in the value-moving fc universe is dropped as
        # out-of-universe (matching the prior Solidity-only behavior), not kept.
        universe = {("nuvavault.go", "payinterest")}  # a tracked Go value-mover
        rows = [{"title": "unhunted-surface target: module.go::ConsensusVersion",
                 "id": "CJP-260", "source": "s"}]
        kept, dropped_term, dropped_oou = ug._fc_credit_filter(rows, universe, set(), None)
        self.assertEqual(kept, [])
        self.assertEqual(dropped_oou, 1)

    def test_go_value_moving_surface_kept_when_in_universe(self):
        # A Go surface that IS an in-universe non-terminal value-mover is KEPT -
        # a genuine gap is never hidden.
        universe = {("nuvavault.go", "payinterest")}
        rows = [{"title": "unhunted-surface target: nuvavault.go::PayInterest",
                 "id": "CJP-X", "source": "s"}]
        kept, _, _ = ug._fc_credit_filter(rows, universe, set(), None)
        self.assertEqual(len(kept), 1)


class TestMiningObligationDrop(unittest.TestCase):
    def test_ungrounded_obligation_detected(self):
        self.assertTrue(ug._is_ungrounded_mining_obligation(
            "[obligation:337060fd0a15] unknown-class-h: mined_findings_hunter_bridge"))

    def test_obligation_with_code_surface_kept(self):
        # An obligation row that DOES carry a code surface is grounded - keep it.
        self.assertFalse(ug._is_ungrounded_mining_obligation(
            "[obligation:deadbeef] accounting: Vault.sol::deposit"))
        self.assertFalse(ug._is_ungrounded_mining_obligation(
            "[obligation:deadbeef] accounting @ payInterest"))

    def test_non_obligation_row_untouched(self):
        # No obligation tag -> never dropped by this filter.
        self.assertFalse(ug._is_ungrounded_mining_obligation(
            "unhunted-surface target: module.go::ConsensusVersion"))


class TestPromptDirExcluded(unittest.TestCase):
    def _write(self, p: Path, text: str) -> None:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def test_dispatch_brief_not_scanned(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            aud = ws / ".auditooor"
            # A dispatch brief quoting the surface/skeleton vocabulary as TEMPLATE
            # text - it must NOT be flagged as an abandoned surface.
            self._write(
                aud / "dispatch_briefs" / "my-lane_enriched.md",
                "# Context\nready_for_poc_planning skeleton; unhunted-surface template.\n",
            )
            # A REAL triage packet with a genuine abandoned in-scope surface must
            # still be flagged (proves the gate is not just globally silenced).
            self._write(
                aud / "prove_top_leads_candidate_judgment_packet.md",
                "### CJP-9 - EQ-9\n- Title: unhunted-surface target: Vault.sol::deposit\n"
                "- State: `ready_for_poc_planning`\n",
            )
            res = ug.evaluate(str(ws))
            titles = " | ".join(r["title"] for r in res["abandoned_surfaces"])
            self.assertNotIn("Context", titles)
            self.assertNotIn("my-lane_enriched", res.get("stats", {}).get("_x", ""))
            # the genuine packet surface is still flagged (no fc ledger to drop it)
            self.assertIn("deposit", titles)
            for r in res["abandoned_surfaces"]:
                self.assertNotIn("dispatch_briefs", r.get("source", ""))


if __name__ == "__main__":
    unittest.main()
