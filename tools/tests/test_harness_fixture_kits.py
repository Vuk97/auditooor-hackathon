#!/usr/bin/env python3
"""Tests for reference/harness-fixture-kits/.

Asserts the directory shape and manifest contract documented in
docs/HARNESS_FIXTURE_KITS.md.

Stdlib-only, hermetic. Each test reads the real repo tree (read-only).
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
KITS_ROOT = REPO_ROOT / "reference" / "harness-fixture-kits"
TOP_INDEX = KITS_ROOT / "INDEX.md"
DOCS_GUIDE = REPO_ROOT / "docs" / "HARNESS_FIXTURE_KITS.md"
PLANNER_CONTRACT = KITS_ROOT / "PLANNER_OUTPUT_CONTRACT.md"

EXPECTED_KITS = [
    "engine_api_payload_chains",
    "hardfork_boundary_payloads",
    "state_root_withdrawals_root_controls",
    "dispute_game_proof_catch_net",
    "clob_order_lifecycles",
    "ctf_fee_conservation",
    "uma_negrisk_resolution",
]

INDEX_REQUIRED_FIELDS = [
    "kit_id",
    "language",
    "status",
    "description",
    "exposed_helpers",
    "example_usage",
    "files",
]

SOURCE_EXTS = {".rs", ".sol"}
SIZE_MIN = 50
SIZE_MAX = 150


class TestKitsDirectoryExists(unittest.TestCase):
    def test_kits_root_present(self):
        self.assertTrue(KITS_ROOT.is_dir(), f"missing: {KITS_ROOT}")

    def test_top_level_index_present(self):
        self.assertTrue(TOP_INDEX.is_file(), f"missing: {TOP_INDEX}")

    def test_docs_guide_present(self):
        self.assertTrue(DOCS_GUIDE.is_file(), f"missing: {DOCS_GUIDE}")

    def test_planner_contract_present(self):
        self.assertTrue(PLANNER_CONTRACT.is_file(), f"missing: {PLANNER_CONTRACT}")


class TestEachKitShape(unittest.TestCase):
    def test_every_expected_kit_directory_exists(self):
        for kit in EXPECTED_KITS:
            with self.subTest(kit=kit):
                self.assertTrue((KITS_ROOT / kit).is_dir(), f"missing kit dir: {kit}")

    def test_every_kit_has_readme(self):
        for kit in EXPECTED_KITS:
            with self.subTest(kit=kit):
                self.assertTrue((KITS_ROOT / kit / "README.md").is_file(),
                                f"missing README.md in {kit}")

    def test_every_kit_has_index_json(self):
        for kit in EXPECTED_KITS:
            with self.subTest(kit=kit):
                self.assertTrue((KITS_ROOT / kit / "INDEX.json").is_file(),
                                f"missing INDEX.json in {kit}")

    def test_every_kit_has_at_least_one_source_file(self):
        for kit in EXPECTED_KITS:
            with self.subTest(kit=kit):
                src = KITS_ROOT / kit / "src"
                self.assertTrue(src.is_dir(), f"missing src/ in {kit}")
                files = [p for p in src.rglob("*") if p.is_file() and p.suffix in SOURCE_EXTS]
                self.assertGreaterEqual(len(files), 1,
                                        f"no source files (.rs/.sol) under {src}")


class TestIndexJsonShape(unittest.TestCase):
    def test_every_index_parses(self):
        for kit in EXPECTED_KITS:
            with self.subTest(kit=kit):
                p = KITS_ROOT / kit / "INDEX.json"
                with p.open() as fh:
                    data = json.load(fh)
                self.assertIsInstance(data, dict, f"{p} root must be object")

    def test_every_index_has_required_fields(self):
        for kit in EXPECTED_KITS:
            with self.subTest(kit=kit):
                with (KITS_ROOT / kit / "INDEX.json").open() as fh:
                    data = json.load(fh)
                for field in INDEX_REQUIRED_FIELDS:
                    self.assertIn(field, data, f"{kit}: missing field {field}")

    def test_kit_id_matches_directory(self):
        for kit in EXPECTED_KITS:
            with self.subTest(kit=kit):
                with (KITS_ROOT / kit / "INDEX.json").open() as fh:
                    data = json.load(fh)
                self.assertEqual(data["kit_id"], kit,
                                 f"kit_id {data['kit_id']} != dir {kit}")

    def test_language_is_known(self):
        valid = {"rust", "solidity"}
        for kit in EXPECTED_KITS:
            with self.subTest(kit=kit):
                with (KITS_ROOT / kit / "INDEX.json").open() as fh:
                    data = json.load(fh)
                self.assertIn(data["language"], valid,
                              f"{kit}: language must be one of {valid}")

    def test_exposed_helpers_have_signatures(self):
        for kit in EXPECTED_KITS:
            with self.subTest(kit=kit):
                with (KITS_ROOT / kit / "INDEX.json").open() as fh:
                    data = json.load(fh)
                helpers = data["exposed_helpers"]
                self.assertIsInstance(helpers, list)
                self.assertGreaterEqual(len(helpers), 1, f"{kit}: no helpers")
                for h in helpers:
                    self.assertIn("name", h)
                    self.assertIn("signature", h)

    def test_example_usage_is_3_to_5_lines(self):
        for kit in EXPECTED_KITS:
            with self.subTest(kit=kit):
                with (KITS_ROOT / kit / "INDEX.json").open() as fh:
                    data = json.load(fh)
                eg = data["example_usage"]
                self.assertIsInstance(eg, list)
                self.assertGreaterEqual(len(eg), 3, f"{kit}: example < 3 lines")
                self.assertLessEqual(len(eg), 5, f"{kit}: example > 5 lines")


class TestSourceFileSizeBounds(unittest.TestCase):
    """Each kit source file must be 50-150 lines (starter-scaffold rule)."""
    def test_each_source_file_within_50_to_150_lines(self):
        for kit in EXPECTED_KITS:
            src = KITS_ROOT / kit / "src"
            for f in src.rglob("*"):
                if not f.is_file() or f.suffix not in SOURCE_EXTS:
                    continue
                with self.subTest(kit=kit, file=f.name):
                    with f.open() as fh:
                        n = sum(1 for _ in fh)
                    self.assertGreaterEqual(n, SIZE_MIN,
                        f"{f}: {n} lines < {SIZE_MIN}")
                    self.assertLessEqual(n, SIZE_MAX,
                        f"{f}: {n} lines > {SIZE_MAX}")


class TestTopLevelIndexCitesAllKits(unittest.TestCase):
    def test_every_kit_named_in_top_index(self):
        text = TOP_INDEX.read_text()
        for kit in EXPECTED_KITS:
            with self.subTest(kit=kit):
                self.assertIn(kit, text,
                              f"top-level INDEX.md missing kit_id: {kit}")

    def test_docs_guide_lists_every_kit(self):
        text = DOCS_GUIDE.read_text()
        for kit in EXPECTED_KITS:
            with self.subTest(kit=kit):
                self.assertIn(kit, text,
                              f"docs/HARNESS_FIXTURE_KITS.md missing: {kit}")


class TestPlannerContractMentionsKits(unittest.TestCase):
    def test_planner_contract_cites_at_least_three_kits(self):
        text = PLANNER_CONTRACT.read_text()
        cited = [k for k in EXPECTED_KITS if k in text]
        self.assertGreaterEqual(len(cited), 3,
            f"PLANNER_OUTPUT_CONTRACT.md cites only {cited}; expected >= 3")


if __name__ == "__main__":
    unittest.main()
