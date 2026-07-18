#!/usr/bin/env python3
"""Fire17 coverage for wave17 regex detectors in the recall scoreboard."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "audit" / "realworld-recall-scoreboard.py"

FIRE16_FIXTURES = {
    "integer-clamp-fee-or-supply-companion-fire16": (
        REPO
        / "detectors"
        / "fixtures"
        / "solidity"
        / "integer_clamp_fee_or_supply_companion_fire16"
        / "vulnerable.sol"
    ),
    "fee-redirect-reserve-or-accrual-fire16": (
        REPO
        / "detectors"
        / "fixtures"
        / "solidity"
        / "fee_redirect_reserve_or_accrual_fire16"
        / "vulnerable.sol"
    ),
}


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "realworld_recall_scoreboard_fire17",
        TOOL,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


class Fire17Wave17LoaderTest(unittest.TestCase):
    def test_wave17_fire16_detectors_are_in_scoreboard_library(self) -> None:
        library = M.load_solidity_wave17_regex_library()
        by_slug = {row["slug"]: row for row in library}

        for slug in FIRE16_FIXTURES:
            with self.subTest(slug=slug):
                row = by_slug.get(slug)
                self.assertIsNotNone(row)
                self.assertEqual(row["engine"], "solidity_regex")
                self.assertEqual(row["target_language"], "solidity")
                self.assertTrue(callable(getattr(row["module"], "scan", None)))
                self.assertEqual(Path(row["source_path"]).parent.name, "wave17")

    def test_scoreboard_runs_wave17_source_scan_detectors_on_solidity_sample(self) -> None:
        library = M.load_solidity_wave17_regex_library()
        by_slug = {row["slug"]: row for row in library}
        originals = (M._compile_sample,)

        try:
            M._compile_sample = lambda *_args, **_kwargs: (object(), None)
            for slug, fixture in FIRE16_FIXTURES.items():
                with self.subTest(slug=slug):
                    row = by_slug[slug]
                    sample = {
                        "slug": f"{slug}-sample",
                        "exclude_detector_slug": "",
                        "engine": "slither_dsl",
                        "vuln_path": fixture,
                        "target_language": "solidity",
                        "severity": "MEDIUM",
                        "attack_class": row["attack_class"],
                        "attack_classes": row["attack_classes"],
                        "source": "fire17-loader-test",
                        "sample_origin": "internal_fixture",
                    }

                    results = M.run_scoreboard(
                        [sample],
                        [row],
                        {
                            "slither_engine": object(),
                            "ast_engine": object(),
                            "cosmos_runner": object(),
                        },
                        quiet=True,
                    )

                    self.assertEqual(len(results), 1)
                    self.assertFalse(results[0]["compile_error"])
                    self.assertIn(slug, results[0]["independent_firing_detectors"])
                    self.assertTrue(results[0]["independent_same_class_fired"])
        finally:
            (M._compile_sample,) = originals


if __name__ == "__main__":
    unittest.main()
