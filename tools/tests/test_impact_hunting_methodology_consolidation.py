#!/usr/bin/env python3
"""REVISE-1 consolidation regression test for the per-impact hunting methodology corpus.

audit/corpus_tags/impact_hunting_methodology.yaml is the schema sibling of
economic_attack_primitives.yaml. The prior canonical file carried only 6 fund-impact
playbooks; REVISE-1 merged all 32 per-impact blocks (6 canonical + 26 sibling files)
into one top-level `playbooks:` list and re-keyed the ungrounded permanent-freeze-funds
corpus anchors.

These assertions are NON-VACUOUS: each one fails on a real regression a future edit
could introduce.

  1. The file parses as YAML and carries the sibling schema id + a `playbooks:` list.
  2. There are exactly 32 distinct impact_id playbooks (the consolidation count); a
     dropped or duplicated block fails this.
  3. The 6 canonical fund-impact playbooks survived the merge (a lossy merge that
     dropped one fails here).
  4. A representative spread of the 26 net-new merged impacts is present (so the merge
     actually pulled the siblings in, not just re-wrote the canonical 6).
  5. The RE-KEY landed: the fabricated bare corpus keys ("permanent-freeze" as an
     attack_class, "freeze"/"permanent-freeze" as a bug_class with the old counts) are
     GONE from the permanent-freeze-funds block, and the real adjacent keys named in
     CRITIC.md are present. A revert of the re-key fails this.
  6. No em-dash / en-dash anywhere (hardcoded formatting rule).
  7. Every block carries an impact_id and a title (the two universally-required keys);
     a block authored without a title fails this.

Offline: parses YAML, no network, no subprocess.
"""
from __future__ import annotations

import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml"
SIBLING = REPO / "audit" / "corpus_tags" / "economic_attack_primitives.yaml"

# The 6 fund-impact playbooks the canonical file owned before consolidation.
CANONICAL_SIX = {
    "direct-theft-funds",
    "protocol-insolvency",
    "permanent-freeze-funds",
    "temporary-freeze-funds",
    "theft-unclaimed-yield",
    "permanent-freeze-yield",
}

# A spread of the 26 net-new merged impacts (must all be present post-merge).
NET_NEW_SAMPLE = {
    "access-control-bypass",
    "arithmetic-precision-corruption",
    "bridge-cross-chain-drain",
    "unauthorized-mint",
    "oracle-manipulation",
    "reentrancy",
    "governance-manipulation",
    "chain-halt-shutdown",
    "chain-split-fork",
    "signature-replay-forgery",
    "liquidation-abuse",
    "gas-theft-fee-vault",
    "share-supply-inflation",
    "crypto-key-recovery-leak",
    "dispute-game-resolution",
    "cross-chain-replay-double-spend",
}

EXPECTED_COUNT = 32


class ImpactHuntingMethodologyConsolidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assertTrueExists = CORPUS.exists()
        cls.text = CORPUS.read_text(encoding="utf-8")
        cls.doc = yaml.safe_load(cls.text)
        cls.playbooks = cls.doc.get("playbooks", [])
        cls.by_id = {b.get("impact_id"): b for b in cls.playbooks}

    def test_01_parses_and_schema_matches_sibling(self):
        self.assertTrue(CORPUS.exists(), f"missing {CORPUS}")
        self.assertEqual(
            self.doc.get("schema"),
            "auditooor.impact_hunting_methodology.v1",
            "schema id must be the per-impact-methodology v1",
        )
        self.assertIsInstance(self.playbooks, list)
        # sibling must exist (this file is declared its sibling)
        self.assertTrue(SIBLING.exists(), "economic_attack_primitives.yaml sibling missing")
        sib = yaml.safe_load(SIBLING.read_text(encoding="utf-8"))
        self.assertEqual(sib.get("schema"), "auditooor.economic_attack_primitive.v1")

    def test_02_exactly_32_distinct_playbooks(self):
        ids = [b.get("impact_id") for b in self.playbooks]
        self.assertEqual(
            len(ids), EXPECTED_COUNT,
            f"expected {EXPECTED_COUNT} playbooks, got {len(ids)}",
        )
        self.assertEqual(
            len(set(ids)), EXPECTED_COUNT,
            f"duplicate impact_id in playbooks list: {sorted(i for i in ids if ids.count(i) > 1)}",
        )
        self.assertEqual(self.doc.get("playbooks_count"), EXPECTED_COUNT)

    def test_03_canonical_six_survived(self):
        missing = CANONICAL_SIX - set(self.by_id)
        self.assertFalse(missing, f"canonical fund-impact playbooks lost in merge: {missing}")

    def test_04_net_new_siblings_merged(self):
        missing = NET_NEW_SAMPLE - set(self.by_id)
        self.assertFalse(missing, f"net-new sibling playbooks not merged: {missing}")

    def test_05_permanent_freeze_funds_rekey(self):
        pf = self.by_id["permanent-freeze-funds"]
        blob = yaml.safe_dump(pf, allow_unicode=True)
        # the fabricated bare keys + their old counts must be GONE
        self.assertNotIn(
            "permanent-freeze, 6 records", blob,
            "stale fabricated attack_class 'permanent-freeze, 6 records' must be re-keyed",
        )
        self.assertNotIn(
            "6 permanent-freeze", blob,
            "stale 'by_attack_class 6 permanent-freeze' must be re-keyed",
        )
        self.assertNotIn(
            "29 freeze", blob,
            "stale bug_class '29 freeze' must be re-keyed",
        )
        # the real adjacent keys named in CRITIC.md must be present
        for real_key in ("permafreeze-on-restart", "token-freeze-bypass",
                         "statechain-permafreeze", "funds-freeze"):
            self.assertIn(
                real_key, blob,
                f"re-keyed real corpus key '{real_key}' must appear in permanent-freeze-funds",
            )

    def test_06_no_em_or_en_dash(self):
        self.assertEqual(self.text.count(chr(0x2014)), 0, "em-dash (U+2014) is banned")
        self.assertEqual(self.text.count(chr(0x2013)), 0, "en-dash (U+2013) is banned")

    def test_07_every_block_has_id_and_title(self):
        for b in self.playbooks:
            iid = b.get("impact_id")
            self.assertTrue(iid, f"a playbook block has no impact_id: {sorted(b)[:6]}")
            self.assertTrue(
                b.get("title"),
                f"playbook '{iid}' has no title (downstream renderers key on it)",
            )


if __name__ == "__main__":
    unittest.main()
