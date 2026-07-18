"""Slice 2 corpus-noise calibration + tier promotion regression tests.

Background: PR #156 demoted six wave-18 detectors A→B because their
`corpus_noise_count` was unset (a Tier-A entry must show <=1 noise hit on
the baseline corpora). The Slice 2 calibration PR runs
`tools/clean-codebase-calibrate.py` against solady, solmate, and
openzeppelin-contracts for these six detectors, persists the per-detector
hit counts in `tools/clean-corpus-noise.json`, and — for those at or below
the threshold — promotes them B→A in `detectors/_tier_registry.yaml`.

This test asserts the post-PR invariants directly, so a future edit that
strips the `corpus_noise_count` field or silently demotes a Tier-A row
without recording a count fails CI.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
REGISTRY = REPO / "detectors" / "_tier_registry.yaml"
NOISE_JSON = REPO / "tools" / "clean-corpus-noise.json"

# The six wave-18 detectors that PR #156 parked at Tier-B pending the
# corpus-noise probe (registry ARGUMENT keys, not YAML filename stems).
SLICE2_DETECTORS = (
    "cached-domain-separator-fork-stale",
    "linkedlist-unbounded-iteration-gas-dos",
    "upgradeable-missing-storage-gap",
    "unique-id-hash-composition-asymmetry",
    "snapshot-vs-live-withdrawable-drift",
    "related-bps-config-invariant-missing",
)

# Tier-A safety claim: <=1 hit aggregated across the three baseline corpora.
TIER_A_NOISE_CAP = 1


def _load_registry() -> dict:
    with REGISTRY.open() as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("tiers", {}) or {}


def _load_noise_report() -> dict:
    with NOISE_JSON.open() as fh:
        return json.load(fh)


class Slice2EntriesHaveCorpusNoiseCount(unittest.TestCase):
    """Each of the six detectors must carry a numeric `corpus_noise_count`
    field in its tier registry row (and a per-corpus breakdown). This is
    the structural invariant — strips/demotions that forget to record the
    measurement break this test."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tiers = _load_registry()

    def test_all_six_detectors_present_in_registry(self) -> None:
        missing = [d for d in SLICE2_DETECTORS if d not in self.tiers]
        self.assertEqual(missing, [], f"missing tier rows: {missing}")

    def test_each_entry_has_corpus_noise_count_int(self) -> None:
        for det in SLICE2_DETECTORS:
            with self.subTest(det=det):
                row = self.tiers[det]
                self.assertIn(
                    "corpus_noise_count", row,
                    f"{det} row is missing `corpus_noise_count` "
                    f"(Slice 2 corpus-noise calibration invariant)",
                )
                count = row["corpus_noise_count"]
                self.assertIsInstance(
                    count, int,
                    f"{det}.corpus_noise_count must be int, got {type(count).__name__}",
                )
                self.assertGreaterEqual(
                    count, 0,
                    f"{det}.corpus_noise_count must be >= 0",
                )

    def test_each_entry_has_per_corpus_breakdown(self) -> None:
        """The aggregated count alone is not auditable. Each row must
        also pin the per-corpus split so a later reviewer can see WHICH
        baseline produced the hit (or that all three were clean)."""
        expected_keys = {"solady", "solmate", "openzeppelin-contracts"}
        for det in SLICE2_DETECTORS:
            with self.subTest(det=det):
                row = self.tiers[det]
                self.assertIn(
                    "corpus_noise_breakdown", row,
                    f"{det} row missing `corpus_noise_breakdown`",
                )
                bd = row["corpus_noise_breakdown"]
                self.assertIsInstance(bd, dict, f"{det} breakdown must be dict")
                self.assertEqual(
                    set(bd), expected_keys,
                    f"{det} breakdown keys must be {expected_keys}, got {set(bd)}",
                )
                # Per-corpus hits must sum to the aggregate noise count.
                self.assertEqual(
                    sum(bd.values()), row["corpus_noise_count"],
                    f"{det}: sum(corpus_noise_breakdown) != corpus_noise_count",
                )


class Slice2TierAssignmentMatchesNoiseProbe(unittest.TestCase):
    """Tier choice is driven by the noise probe: <=1 hit aggregated across
    corpora qualifies for Tier-A; >1 stays B with a transparency flag.
    No detector may sit at Tier-A while exceeding the cap."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tiers = _load_registry()

    def test_tier_a_rows_respect_noise_cap(self) -> None:
        for det in SLICE2_DETECTORS:
            with self.subTest(det=det):
                row = self.tiers[det]
                tier = row.get("tier")
                count = row.get("corpus_noise_count", -1)
                if tier == "A":
                    self.assertLessEqual(
                        count, TIER_A_NOISE_CAP,
                        f"{det} sits at Tier-A but corpus_noise_count={count} "
                        f"exceeds Tier-A cap of {TIER_A_NOISE_CAP}",
                    )
                elif tier == "B":
                    # If still at B, the row must explain why with the
                    # block flag (transparency requirement from the PR).
                    self.assertTrue(
                        row.get("pending_promotion_to_a_blocked_by_noise") is True,
                        f"{det} stayed at Tier-B but lacks "
                        f"`pending_promotion_to_a_blocked_by_noise: true` flag",
                    )
                else:
                    self.fail(
                        f"{det} has unexpected tier {tier!r} — must be A or B",
                    )


class Slice2NoiseJsonHasAllSixEntries(unittest.TestCase):
    """The aggregated `tools/clean-corpus-noise.json` must hold a
    per_detector slot for each of the six detectors so future runs can
    diff against this baseline."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _load_noise_report()

    def test_per_detector_contains_six(self) -> None:
        per_det = self.report.get("per_detector", {})
        for det in SLICE2_DETECTORS:
            with self.subTest(det=det):
                self.assertIn(
                    det, per_det,
                    f"{det} missing from clean-corpus-noise.json — "
                    f"Slice 2 calibration was not recorded",
                )
                slot = per_det[det]
                self.assertIn("by_corpus", slot)
                self.assertEqual(
                    set(slot["by_corpus"]),
                    {"solady", "solmate", "openzeppelin-contracts"},
                    f"{det} by_corpus keys mismatch",
                )

    def test_registry_count_matches_json_total(self) -> None:
        per_det = self.report.get("per_detector", {})
        tiers = _load_registry()
        for det in SLICE2_DETECTORS:
            with self.subTest(det=det):
                if det not in per_det:
                    continue
                json_total = per_det[det]["total_hits"]
                registry_count = tiers[det].get("corpus_noise_count")
                self.assertEqual(
                    json_total, registry_count,
                    f"{det}: clean-corpus-noise.json total_hits={json_total} "
                    f"!= registry corpus_noise_count={registry_count}",
                )


if __name__ == "__main__":
    unittest.main()
