#!/usr/bin/env python3
"""Tests for tools/bug_bounty_oos_index.py."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "bug_bounty_oos_index.py"
_spec = importlib.util.spec_from_file_location("bug_bounty_oos_index", _TOOL_PATH)
bb_oos = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(bb_oos)


class BugBountyOosIndexTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "workspace"
        self.ws.mkdir(parents=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_builds_index_from_root_and_src_bug_bounty_files(self) -> None:
        (self.ws / "BUG_BOUNTY.md").write_text(
            "\n".join(
                [
                    "# Program",
                    "",
                    "## Out of Scope",
                    "",
                    "- Front-running / sandwich / MEV via public mempool is OOS.",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        src = self.ws / "src" / "superearn"
        src.mkdir(parents=True)
        (src / "BUG_BOUNTY.md").write_text(
            "\n".join(
                [
                    "# SuperEarn",
                    "",
                    "## AI-Tool False-Positive Patterns",
                    "",
                    "| Row | Pattern |",
                    "| --- | --- |",
                    "| 42 | Front-running via public mempool against minOut flows |",
                    "",
                    "## Known Issues / Acknowledged Design Decisions",
                    "",
                    "| ID | Issue |",
                    "| --- | --- |",
                    "| SE-P13 | Hypothetical stablecoin fee-on-transfer asset behavior is known OOS |",
                    "",
                    "## Trust Assumptions",
                    "",
                    "Stablecoin issuers are trusted for freeze and fee-on-transfer behavior.",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        index = bb_oos.build_and_write_index(self.ws)
        index_path = self.ws.resolve() / ".auditooor" / "bug_bounty_oos_index.json"

        self.assertTrue(index_path.is_file())
        persisted = json.loads(index_path.read_text(encoding="utf-8"))
        self.assertEqual(index["schema"], bb_oos.SCHEMA)
        self.assertEqual(persisted["schema"], bb_oos.SCHEMA)
        self.assertIn("BUG_BOUNTY.md", index["source_paths"])
        self.assertIn("src/superearn/BUG_BOUNTY.md", index["source_paths"])
        clause_ids = {row["clause_id"] for row in index["rows"]}
        self.assertIn("AI-FP-row-42", clause_ids)
        self.assertIn("SE-P13", clause_ids)
        trust_rows = [row for row in index["rows"] if row["section"] == "trust_assumption"]
        self.assertTrue(trust_rows)
        self.assertIn("stablecoin-trust", trust_rows[0]["semantic_tags"])

    def test_matches_superearn_front_running_and_trusted_stablecoin_fee_on_transfer(self) -> None:
        index = {
            "schema": bb_oos.SCHEMA,
            "rows": [
                {
                    "clause_id": "AI-FP-row-42",
                    "section": "ai_false_positive",
                    "phrase": "Front-running / sandwich / MEV via public mempool against contracts using 2-step request/claim or minOut",
                    "semantic_tags": [
                        "ai-fp",
                        "front-running-public-mempool",
                        "slippage",
                    ],
                    "source_path": "src/superearn/BUG_BOUNTY.md",
                    "line_start": 42,
                },
                {
                    "clause_id": "TRUST-L379",
                    "section": "trust_assumption",
                    "phrase": "Stablecoin issuers are trusted for fee-on-transfer behavior",
                    "semantic_tags": [
                        "trust-assumption",
                        "stablecoin",
                        "stablecoin-trust",
                        "fee-on-transfer",
                    ],
                    "source_path": "src/superearn/BUG_BOUNTY.md",
                    "line_start": 379,
                },
            ],
        }
        front = {
            "cluster_id": "erc4626-functions-no-slippage",
            "file_line": "src/vaults/OriginVaultBase.sol:193",
            "snippet": "2-step request/claim vault flow lacks minOut",
            "matched_p1_invariants": ["INV-ERC4626-001"],
        }
        stablecoin_fot = {
            "cluster_id": "fee-on-transfer-not-accounted",
            "file_line": "src/vaults/CooldownVault.sol:902",
            "snippet": "stablecoin fee-on-transfer not accounted before minting shares",
            "matched_p1_invariants": ["INV-CON-001"],
        }

        front_match = bb_oos.match_candidate(front, index)
        fot_match = bb_oos.match_candidate(stablecoin_fot, index)

        self.assertIsNotNone(front_match)
        self.assertEqual(front_match["clause_id"], "AI-FP-row-42")
        self.assertGreaterEqual(front_match["confidence"], 0.7)
        self.assertTrue(front_match["requires_extension_distinct_argument"])
        self.assertIsNotNone(fot_match)
        self.assertEqual(fot_match["clause_id"], "TRUST-L379")
        self.assertGreaterEqual(fot_match["confidence"], 0.7)
        self.assertTrue(fot_match["requires_extension_distinct_argument"])


if __name__ == "__main__":
    unittest.main()
