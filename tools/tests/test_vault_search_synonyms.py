"""Smoke test for reference/vault_search_synonyms.yaml.

Validates (existing assertions):
- YAML loads without error
- schema_version == 1
- synonyms list has >= 50 entries
- each entry has: canonical, expands_to (non-empty list), context_tags (non-empty list)

Additional assertions (W2-D2 brief requirements):
- schema field == "auditooor.vault_search_synonyms.v1"
- groups list has >= 10 entries
- every group has canonical + aliases (non-empty) + domain
- no duplicate canonical terms within groups
- all aliases are unique within their own group
- at least one Spark group, one FROST group, one consensus-generic group
"""
import os
import unittest
import yaml

YAML_PATH = os.path.join(
    os.path.dirname(__file__),  # tools/tests/
    "..", "..",                 # worktree root
    "reference", "vault_search_synonyms.yaml",
)


class TestVaultSearchSynonyms(unittest.TestCase):

    def setUp(self):
        with open(os.path.normpath(YAML_PATH), "r") as fh:
            self.data = yaml.safe_load(fh)

    # ── Existing tests (synonyms[] section) ──────────────────────────────────

    def test_schema_version_is_1(self):
        self.assertEqual(self.data.get("schema_version"), 1)

    def test_at_least_50_synonym_entries(self):
        synonyms = self.data.get("synonyms", [])
        self.assertGreaterEqual(len(synonyms), 50, f"Expected >= 50 rows, got {len(synonyms)}")

    def test_each_entry_has_canonical(self):
        for i, entry in enumerate(self.data.get("synonyms", [])):
            self.assertIn("canonical", entry, f"Row {i} missing 'canonical'")
            self.assertIsInstance(entry["canonical"], str, f"Row {i} 'canonical' not a string")
            self.assertTrue(entry["canonical"].strip(), f"Row {i} 'canonical' is empty")

    def test_each_entry_has_non_empty_expands_to(self):
        for i, entry in enumerate(self.data.get("synonyms", [])):
            self.assertIn("expands_to", entry, f"Row {i} missing 'expands_to'")
            self.assertIsInstance(entry["expands_to"], list, f"Row {i} 'expands_to' not a list")
            self.assertGreater(len(entry["expands_to"]), 0, f"Row {i} 'expands_to' is empty")

    def test_each_entry_has_non_empty_context_tags(self):
        for i, entry in enumerate(self.data.get("synonyms", [])):
            self.assertIn("context_tags", entry, f"Row {i} missing 'context_tags'")
            self.assertIsInstance(entry["context_tags"], list, f"Row {i} 'context_tags' not a list")
            self.assertGreater(len(entry["context_tags"]), 0, f"Row {i} 'context_tags' is empty")

    # ── W2-D2 brief requirements (groups[] section) ──────────────────────────

    def test_schema_field_is_v1_string(self):
        """Brief requirement: schema == 'auditooor.vault_search_synonyms.v1'"""
        self.assertEqual(
            self.data.get("schema"),
            "auditooor.vault_search_synonyms.v1",
            "Top-level 'schema' field must be 'auditooor.vault_search_synonyms.v1'",
        )

    def test_groups_list_has_at_least_10_entries(self):
        """Brief requirement: >= 10 groups in the groups[] section"""
        groups = self.data.get("groups", [])
        self.assertGreaterEqual(
            len(groups), 10,
            f"Expected >= 10 groups, got {len(groups)}",
        )

    def test_every_group_has_canonical(self):
        """Brief requirement: every group has canonical"""
        for i, grp in enumerate(self.data.get("groups", [])):
            self.assertIn("canonical", grp, f"groups[{i}] missing 'canonical'")
            self.assertIsInstance(grp["canonical"], str, f"groups[{i}] 'canonical' not a string")
            self.assertTrue(grp["canonical"].strip(), f"groups[{i}] 'canonical' is empty")

    def test_every_group_has_non_empty_aliases(self):
        """Brief requirement: every group has aliases (non-empty list)"""
        for i, grp in enumerate(self.data.get("groups", [])):
            self.assertIn("aliases", grp, f"groups[{i}] missing 'aliases'")
            self.assertIsInstance(grp["aliases"], list, f"groups[{i}] 'aliases' not a list")
            self.assertGreater(len(grp["aliases"]), 0, f"groups[{i}] 'aliases' is empty")

    def test_every_group_has_domain(self):
        """Brief requirement: every group has domain"""
        valid_domains = {"frost", "statechain", "spark", "cosmos", "cometbft", "btc",
                         "consensus", "misc"}
        for i, grp in enumerate(self.data.get("groups", [])):
            self.assertIn("domain", grp, f"groups[{i}] missing 'domain'")
            self.assertIn(
                grp["domain"], valid_domains,
                f"groups[{i}] domain '{grp['domain']}' not in valid set {valid_domains}",
            )

    def test_no_duplicate_canonical_terms_in_groups(self):
        """Brief requirement: no duplicate canonical terms within groups"""
        canonicals = [grp["canonical"] for grp in self.data.get("groups", [])]
        seen = set()
        duplicates = []
        for c in canonicals:
            if c in seen:
                duplicates.append(c)
            seen.add(c)
        self.assertEqual(
            duplicates, [],
            f"Duplicate canonical terms in groups: {duplicates}",
        )

    def test_aliases_unique_within_each_group(self):
        """Brief requirement: all aliases are unique within their group"""
        for i, grp in enumerate(self.data.get("groups", [])):
            aliases = grp.get("aliases", [])
            seen = set()
            dups = []
            for a in aliases:
                if a in seen:
                    dups.append(a)
                seen.add(a)
            self.assertEqual(
                dups, [],
                f"groups[{i}] (canonical='{grp.get('canonical')}') has duplicate aliases: {dups}",
            )

    def test_at_least_one_spark_group(self):
        """Brief requirement: at least one Spark domain group"""
        spark_groups = [g for g in self.data.get("groups", []) if g.get("domain") == "spark"]
        self.assertGreater(
            len(spark_groups), 0,
            "No groups with domain='spark' found — required by W2-D2 brief",
        )

    def test_at_least_one_frost_group(self):
        """Brief requirement: at least one FROST domain group"""
        frost_groups = [g for g in self.data.get("groups", []) if g.get("domain") == "frost"]
        self.assertGreater(
            len(frost_groups), 0,
            "No groups with domain='frost' found — required by W2-D2 brief",
        )

    def test_at_least_one_consensus_generic_group(self):
        """Brief requirement: at least one consensus-generic group (consensus, btc, cometbft)"""
        consensus_domains = {"consensus", "btc", "cometbft"}
        consensus_groups = [
            g for g in self.data.get("groups", [])
            if g.get("domain") in consensus_domains
        ]
        self.assertGreater(
            len(consensus_groups), 0,
            f"No groups with domain in {consensus_domains} found — required by W2-D2 brief",
        )

    def test_spark_group_covers_coop_exit(self):
        """Spot-check: coop_exit canonical must be present"""
        canonicals = {g["canonical"] for g in self.data.get("groups", [])}
        self.assertIn("coop_exit", canonicals, "groups must include 'coop_exit' canonical")

    def test_frost_group_covers_frost_canonical(self):
        """Spot-check: FROST canonical must be present with threshold-signing as alias"""
        frost_groups = [g for g in self.data.get("groups", []) if g.get("canonical") == "FROST"]
        self.assertEqual(len(frost_groups), 1, "Exactly one group with canonical='FROST' expected")
        aliases = frost_groups[0].get("aliases", [])
        self.assertIn(
            "threshold-signing", aliases,
            "'threshold-signing' must be an alias of the 'FROST' group",
        )

    # ── W2-CATCHUP-D2 (iter 18): rows 52-55 hacker-mindset vocabulary ────────

    def test_total_rows_field_is_55(self):
        """Iter 18 catchup: total_rows top-level field must equal 55 (51-row gap closed)."""
        self.assertEqual(
            self.data.get("total_rows"), 55,
            f"Expected total_rows == 55, got {self.data.get('total_rows')}",
        )

    def test_synonyms_section_has_at_least_55_rows(self):
        """Iter 18 catchup: synonyms[] section must reach the 55-row spec target."""
        synonyms = self.data.get("synonyms", [])
        self.assertGreaterEqual(
            len(synonyms), 55,
            f"Expected >= 55 synonyms rows, got {len(synonyms)}",
        )

    def test_iter18_new_canonicals_present(self):
        """Iter 18 catchup: 4 new hacker-mindset canonicals must be present."""
        expected = {
            "attacker viewpoint",
            "exploit angle augmentation",
            "red-team prompt",
            "attack surface expansion",
        }
        canonicals = {row["canonical"] for row in self.data.get("synonyms", [])}
        missing = expected - canonicals
        self.assertEqual(
            missing, set(),
            f"Iter 18 catchup rows missing from synonyms[]: {missing}",
        )

    def test_iter18_new_canonicals_have_at_least_3_synonyms_each(self):
        """Iter 18 catchup: each new row must have >= 3 expands_to tokens."""
        new_rows = {
            "attacker viewpoint",
            "exploit angle augmentation",
            "red-team prompt",
            "attack surface expansion",
        }
        for row in self.data.get("synonyms", []):
            if row.get("canonical") in new_rows:
                expansions = row.get("expands_to", [])
                self.assertGreaterEqual(
                    len(expansions), 3,
                    f"Row '{row['canonical']}' has fewer than 3 expands_to tokens: {expansions}",
                )

    def test_iter18_rows_resolve_to_adversarial_artifacts(self):
        """Iter 18 catchup: each new row's artifact_hints must include adversarial-copilot path."""
        new_rows = {
            "attacker viewpoint",
            "exploit angle augmentation",
            "red-team prompt",
            "attack surface expansion",
        }
        for row in self.data.get("synonyms", []):
            if row.get("canonical") in new_rows:
                hints = row.get("artifact_hints", []) or []
                joined = " ".join(hints)
                self.assertIn(
                    "adversarial-copilot.py", joined,
                    f"Row '{row['canonical']}' artifact_hints must reference "
                    f"tools/adversarial-copilot.py (FM-1 anchor); got {hints}",
                )

    def test_iter18_rows_have_unique_source_row_numbers(self):
        """Iter 18 catchup: rows 52-55 must be uniquely numbered in source_row."""
        new_rows = {
            "attacker viewpoint",
            "exploit angle augmentation",
            "red-team prompt",
            "attack surface expansion",
        }
        observed = {}
        for row in self.data.get("synonyms", []):
            if row.get("canonical") in new_rows:
                sr = row.get("source_row")
                self.assertIsNotNone(
                    sr, f"Row '{row['canonical']}' missing source_row",
                )
                self.assertIn(
                    sr, {52, 53, 54, 55},
                    f"Row '{row['canonical']}' source_row {sr} not in 52-55",
                )
                self.assertNotIn(
                    sr, observed,
                    f"Duplicate source_row {sr} (collides with '{observed.get(sr)}')",
                )
                observed[sr] = row["canonical"]
        self.assertEqual(
            len(observed), 4,
            f"Expected 4 catchup rows numbered 52-55, found {len(observed)}: {observed}",
        )


if __name__ == "__main__":
    unittest.main()
