"""
Tests for the Wave-2 W2.2 Phase-1 detector roster.

Roster lives at: tools/audit/detector_previews/wave2_w22_phase1_roster.json
Spec contract:   docs/WAVE2_W22_DETECTOR_AUTOGEN_SPEC_2026-05-16.md (section 10)

The roster is PREVIEW-only - no live corpus scanning, no PoC generation,
no make-audit wiring. These tests enforce the structural contract so
later W2.2.a (synthesiser) + W2.2.c (operator PR-review) passes can
ratchet against a known shape.
"""

from __future__ import annotations

import json
import unittest
from collections import Counter
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROSTER_PATH = REPO_ROOT / "tools" / "audit" / "detector_previews" / "wave2_w22_phase1_roster.json"
MARKDOWN_PATH = REPO_ROOT / "docs" / "WAVE2_W22_PHASE1_ROSTER_2026-05-16.md"
FIXTURE_DIR = REPO_ROOT / "tools" / "audit" / "detector_fixtures" / "wave2_w22"

ALLOWED_LANGUAGES = {"solidity", "vyper", "go", "rust", "circom"}
ALLOWED_SEVERITIES = {"HIGH", "CRITICAL"}
ALLOWED_STATUS = {"preview"}

REQUIRED_FIELDS = (
    "detector_id",
    "language",
    "attack_class",
    "severity_floor",
    "source_record_id",
    "status",
)


def _load_roster() -> dict:
    with ROSTER_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


class Wave2W22Phase1RosterTests(unittest.TestCase):
    """Structural contract tests for the Phase-1 roster JSON + markdown."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.roster = _load_roster()
        cls.detectors = cls.roster["detectors"]

    # ---- shape tests ----

    def test_01_roster_file_exists_and_loads(self) -> None:
        self.assertTrue(ROSTER_PATH.is_file(), f"roster JSON missing: {ROSTER_PATH}")
        self.assertIsInstance(self.roster, dict)
        self.assertIn("detectors", self.roster)
        self.assertIsInstance(self.detectors, list)

    def test_02_envelope_has_schema_and_provenance(self) -> None:
        self.assertEqual(
            self.roster.get("schema"),
            "auditooor.wave2_w22_phase1_roster.v1",
            "envelope.schema must match v1",
        )
        self.assertEqual(self.roster.get("phase"), "wave2_w22_phase_1")
        self.assertEqual(self.roster.get("detector_count"), 20)
        prov = self.roster.get("provenance", {})
        self.assertIn("context_pack_id", prov)
        self.assertIn("context_pack_hash", prov)
        self.assertTrue(prov["context_pack_hash"], "context_pack_hash must be non-empty")

    def test_03_exactly_twenty_entries(self) -> None:
        self.assertEqual(
            len(self.detectors),
            20,
            f"phase-1 roster must have exactly 20 detectors, got {len(self.detectors)}",
        )

    def test_04_required_fields_present_on_every_entry(self) -> None:
        for idx, det in enumerate(self.detectors):
            for field in REQUIRED_FIELDS:
                self.assertIn(field, det, f"entry #{idx} missing field '{field}'")
                self.assertIsNotNone(det[field], f"entry #{idx} has null '{field}'")

    # ---- field-value tests ----

    def test_05_all_status_preview(self) -> None:
        for idx, det in enumerate(self.detectors):
            self.assertIn(
                det["status"],
                ALLOWED_STATUS,
                f"entry #{idx} ({det['detector_id']}) status={det['status']!r} not in {ALLOWED_STATUS}",
            )

    def test_06_severity_floor_in_high_or_critical(self) -> None:
        for idx, det in enumerate(self.detectors):
            self.assertIn(
                det["severity_floor"],
                ALLOWED_SEVERITIES,
                f"entry #{idx} ({det['detector_id']}) severity_floor={det['severity_floor']!r}",
            )

    def test_07_languages_from_allowed_set(self) -> None:
        for idx, det in enumerate(self.detectors):
            self.assertIn(
                det["language"],
                ALLOWED_LANGUAGES,
                f"entry #{idx} ({det['detector_id']}) language={det['language']!r} not in {ALLOWED_LANGUAGES}",
            )

    def test_08_attack_class_and_source_record_id_nonempty(self) -> None:
        for idx, det in enumerate(self.detectors):
            self.assertTrue(
                isinstance(det["attack_class"], str) and det["attack_class"].strip(),
                f"entry #{idx} ({det['detector_id']}) attack_class is empty",
            )
            self.assertTrue(
                isinstance(det["source_record_id"], str) and det["source_record_id"].strip(),
                f"entry #{idx} ({det['detector_id']}) source_record_id is empty",
            )

    def test_09_source_record_id_uses_known_prefix(self) -> None:
        """source_record_id must be prefixed git-mining: or ghsa: per task spec."""
        allowed_prefixes = ("git-mining:", "ghsa:")
        for idx, det in enumerate(self.detectors):
            self.assertTrue(
                det["source_record_id"].startswith(allowed_prefixes),
                f"entry #{idx} ({det['detector_id']}) source_record_id={det['source_record_id']!r} "
                f"must start with one of {allowed_prefixes}",
            )

    def test_10_detector_id_unique_and_w22_prefixed(self) -> None:
        ids = [d["detector_id"] for d in self.detectors]
        self.assertEqual(len(ids), len(set(ids)), "detector_id values must be unique")
        for det_id in ids:
            self.assertTrue(
                det_id.startswith("w22_"),
                f"detector_id {det_id!r} must start with 'w22_' (phase-1 convention)",
            )

    def test_11_language_distribution_matches_spec(self) -> None:
        """Spec §10: 6 go + 6 solidity + 4 vyper + 2 rust + 2 circom = 20."""
        counts = Counter(d["language"] for d in self.detectors)
        self.assertEqual(counts["go"], 6, f"expected 6 go entries, got {counts['go']}")
        self.assertEqual(counts["solidity"], 6, f"expected 6 solidity entries, got {counts['solidity']}")
        self.assertEqual(counts["vyper"], 4, f"expected 4 vyper entries, got {counts['vyper']}")
        self.assertEqual(counts["rust"], 2, f"expected 2 rust entries, got {counts['rust']}")
        self.assertEqual(counts["circom"], 2, f"expected 2 circom entries, got {counts['circom']}")

    def test_12_first_five_match_existing_fixture_templates(self) -> None:
        """Rows 1-5 must align with the 5 fixture templates shipped at 474b352f03."""
        expected_first_five = [
            "w22_sol_reentrancy_curve_stable",
            "w22_vy_reentrancy_curve_ib",
            "w22_go_cometbft_validate_basic",
            "w22_rs_l2_zksolc_compile",
            "w22_circom_under_constrained",
        ]
        actual_first_five = [d["detector_id"] for d in self.detectors[:5]]
        self.assertEqual(actual_first_five, expected_first_five)
        # Verify each fixture directory actually exists on disk.
        for det_id in expected_first_five:
            self.assertTrue(
                (FIXTURE_DIR / det_id).is_dir(),
                f"fixture template dir missing: {FIXTURE_DIR / det_id}",
            )

    def test_13_deterministic_ordering(self) -> None:
        """Re-loading the JSON must produce identical detector order (stable on disk)."""
        again = _load_roster()
        self.assertEqual(
            [d["detector_id"] for d in self.detectors],
            [d["detector_id"] for d in again["detectors"]],
        )

    def test_14_markdown_exists_and_lists_all_twenty(self) -> None:
        self.assertTrue(MARKDOWN_PATH.is_file(), f"markdown roster missing: {MARKDOWN_PATH}")
        body = MARKDOWN_PATH.read_text(encoding="utf-8")
        for det in self.detectors:
            self.assertIn(
                det["detector_id"],
                body,
                f"markdown must reference detector_id {det['detector_id']}",
            )


if __name__ == "__main__":
    unittest.main()
