from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-fixture-regression-list.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("rust_fixture_regression_list", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["rust_fixture_regression_list"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")


class RustFixtureRegressionListTests(unittest.TestCase):
    def test_report_appends_only_fixture_backed_top_level_detectors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write(
                repo / "detectors" / "rust_wave1" / "test_fixtures" / "test_detectors.sh",
                """
                DETECTORS=(
                  already_listed
                )
                """,
            )
            _write(repo / "detectors" / "rust_wave1" / "already_listed.py", "def run(): return []")
            _write(repo / "detectors" / "rust_wave1" / "missing_hook.py", "def run(): return []")
            fixtures = repo / "detectors" / "rust_wave1" / "test_fixtures"
            for detector in ("already_listed", "missing_hook", "nested_skip"):
                _write(fixtures / f"{detector}_positive.rs", "fn positive() {}")
                _write(fixtures / f"{detector}_negative.rs", "fn negative() {}")
            report = repo / "reports" / "rust_detector_coverage_2026-05-05.json"
            _write(
                report,
                json.dumps(
                    {
                        "missing_runner_hook": {
                            "detectors": [
                                {
                                    "detector_id": "missing_hook",
                                    "fixture_pair_present": True,
                                    "nested_detector": False,
                                    "detector_group": "rust_wave1",
                                },
                                {
                                    "detector_id": "nested_skip",
                                    "fixture_pair_present": True,
                                    "nested_detector": True,
                                    "detector_group": "nested",
                                },
                                {
                                    "detector_id": "fixtureless_skip",
                                    "fixture_pair_present": False,
                                    "nested_detector": False,
                                    "detector_group": "rust_wave1",
                                },
                            ]
                        }
                    }
                ),
            )

            detectors, skipped = MOD.build_regression_list(repo, report)

            self.assertEqual(detectors, ["already_listed", "missing_hook"])
            self.assertEqual(skipped, ["nested_skip", "fixtureless_skip"])

    def test_per_detector_rows_keep_fixture_backed_covered_detectors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write(
                repo / "detectors" / "rust_wave1" / "test_fixtures" / "test_detectors.sh",
                """
                DETECTORS=(
                  static_only
                )
                """,
            )
            _write(repo / "detectors" / "rust_wave1" / "static_only.py", "def run(): return []")
            _write(
                repo / "detectors" / "rust_wave1" / "covered_in_report.py",
                "def run(): return []",
            )
            fixtures = repo / "detectors" / "rust_wave1" / "test_fixtures"
            _write(fixtures / "covered_in_report_positive.rs", "fn positive() {}")
            _write(fixtures / "covered_in_report_negative.rs", "fn negative() {}")
            report = repo / "reports" / "rust_detector_coverage_2026-05-05.json"
            _write(
                report,
                json.dumps(
                    {
                        "per_detector": [
                            {
                                "detector_id": "covered_in_report",
                                "fixture_pair_present": True,
                                "missing_runner_hook": False,
                                "full_regression_script_covered": True,
                                "listed_in_full_regression_script": True,
                                "nested_detector": False,
                                "detector_group": "rust_wave1",
                            }
                        ]
                    }
                ),
            )

            detectors, skipped = MOD.build_regression_list(repo, report)

            self.assertEqual(detectors, ["static_only", "covered_in_report"])
            self.assertEqual(skipped, [])

    def test_static_nested_detector_is_not_reported_as_residual_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write(
                repo / "detectors" / "rust_wave1" / "test_fixtures" / "test_detectors.sh",
                """
                DETECTORS=(
                  static_nested
                )
                """,
            )
            _write(
                repo / "detectors" / "rust_wave1" / "nested_group" / "static_nested.py",
                "def run(): return []",
            )
            fixtures = repo / "detectors" / "rust_wave1" / "test_fixtures"
            _write(fixtures / "static_nested_positive.rs", "fn positive() {}")
            _write(fixtures / "static_nested_negative.rs", "fn negative() {}")
            report = repo / "reports" / "rust_detector_coverage_2026-05-05.json"
            _write(
                report,
                json.dumps(
                    {
                        "per_detector": [
                            {
                                "detector_id": "static_nested",
                                "fixture_pair_present": True,
                                "nested_detector": True,
                                "detector_group": "nested_group",
                            }
                        ]
                    }
                ),
            )

            detectors, skipped = MOD.build_regression_list(repo, report)

            self.assertEqual(detectors, ["static_nested"])
            self.assertEqual(skipped, [])

    def test_missing_report_preserves_static_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write(
                repo / "detectors" / "rust_wave1" / "test_fixtures" / "test_detectors.sh",
                """
                DETECTORS=(
                  static_only
                )
                """,
            )

            detectors, skipped = MOD.build_regression_list(repo, repo / "reports" / "missing.json")

            self.assertEqual(detectors, ["static_only"])
            self.assertEqual(skipped, [])


if __name__ == "__main__":
    unittest.main()
