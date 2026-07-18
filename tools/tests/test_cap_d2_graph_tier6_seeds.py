"""CAP-D2 Tier-6 seed corpus integrity test.

Asserts the graphprotocol/contracts Tier-6 mining report emits detector
pattern seeds that each carry a non-empty Rule-37 verification_tier and a
resolvable GitHub commit source URL. No network access: the SHA-vs-URL
self-consistency check is purely structural.
"""
from __future__ import annotations

import json
import pathlib
import re
import unittest


REPO = pathlib.Path(__file__).resolve().parents[2]
REPORT = (
    REPO
    / "reports"
    / "git_commits_mining_graphprotocol-contracts_cap-d2_2026-05-16.json"
)

VALID_TIERS = {
    "tier-1-verified-realtime-api",
    "tier-1-officially-disclosed",
    "tier-2-verified-public-archive",
    "tier-3-synthetic-taxonomy-anchored",
    "tier-4-bundled-fixture",
    "tier-5-quarantine",
}

COMMIT_URL_RE = re.compile(
    r"^https://github\.com/graphprotocol/contracts/commit/([0-9a-f]{40})$"
)


class CapD2GraphTier6SeedsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with REPORT.open(encoding="utf-8") as fh:
            cls.report = json.load(fh)
        cls.seeds = cls.report["derivable_detector_pattern_seeds"]

    def test_report_exists_and_is_capability_only(self) -> None:
        self.assertTrue(REPORT.exists(), f"missing report: {REPORT}")
        self.assertIs(self.report["capability_only"], True)
        self.assertEqual(self.report["upstream_repo"], "graphprotocol/contracts")

    def test_seeds_present(self) -> None:
        self.assertGreaterEqual(len(self.seeds), 1, "no seeds emitted")

    def test_every_seed_has_non_empty_verification_tier(self) -> None:
        for seed in self.seeds:
            tier = seed.get("verification_tier")
            self.assertIn(
                tier,
                VALID_TIERS,
                f"seed {seed.get('id')} has invalid/missing verification_tier: {tier!r}",
            )
            self.assertTrue(
                isinstance(tier, str) and tier.strip(),
                f"seed {seed.get('id')} verification_tier is empty",
            )

    def test_every_seed_has_resolvable_commit_source_url(self) -> None:
        for seed in self.seeds:
            url = seed.get("record_source_url", "")
            m = COMMIT_URL_RE.match(url or "")
            self.assertIsNotNone(
                m,
                f"seed {seed.get('id')} record_source_url not a resolvable "
                f"graphprotocol/contracts commit URL: {url!r}",
            )
            # URL SHA must match the seed's declared source_commit_sha (no fabrication).
            self.assertEqual(
                m.group(1),
                seed.get("source_commit_sha"),
                f"seed {seed.get('id')} URL SHA != source_commit_sha",
            )

    def test_every_shaped_commit_url_matches_sha(self) -> None:
        for c in self.report["shaped_commits"]:
            m = COMMIT_URL_RE.match(c.get("url", ""))
            self.assertIsNotNone(
                m, f"shaped commit {c.get('sha')} has non-resolvable url"
            )
            self.assertEqual(m.group(1), c["sha"])

    def test_tier2_seeds_carry_min_shape_fields(self) -> None:
        # Rule 37: tier-2 requires >=3 mandatory shape fields extracted.
        for seed in self.seeds:
            if seed["verification_tier"] == "tier-2-verified-public-archive":
                fields = seed.get("shape_fields_extracted", [])
                self.assertGreaterEqual(
                    len(fields),
                    3,
                    f"seed {seed.get('id')} tier-2 but <3 shape fields",
                )

    def test_taxonomy_buckets_valid(self) -> None:
        for seed in self.seeds:
            self.assertIn(seed.get("taxonomy_bucket"), {"a", "b", "c", "d"})


if __name__ == "__main__":
    unittest.main()
