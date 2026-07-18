#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "detector-precision-matrix.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("detector_precision_matrix", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DetectorPrecisionMatrixSelectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_module()
        self.detectors = [
            {"name": "swap-missing-slippage-protection", "argument": "swap-missing-slippage-protection", "tier": "A"},
            {"name": "flashloan_callback_missing_initiator_check", "argument": "flashloan-callback-missing-initiator-check", "tier": "B"},
        ]

    def test_parse_args_accepts_detector(self) -> None:
        args = self.mod.parse_args(["--detector", "swap-missing-slippage-protection"])
        self.assertEqual(args.detector, "swap-missing-slippage-protection")

    def test_parse_args_rejects_detector_with_sample_detectors(self) -> None:
        with self.assertRaises(SystemExit):
            self.mod.parse_args(["--detector", "x", "--sample-detectors", "2"])

    def test_resolve_selected_detector_prefers_exact_name(self) -> None:
        row = self.mod.resolve_selected_detector(self.detectors, "flashloan_callback_missing_initiator_check")
        self.assertEqual(row["argument"], "flashloan-callback-missing-initiator-check")

    def test_resolve_selected_detector_falls_back_to_argument(self) -> None:
        row = self.mod.resolve_selected_detector(self.detectors, "swap-missing-slippage-protection")
        self.assertEqual(row["name"], "swap-missing-slippage-protection")

    def test_resolve_selected_detector_rejects_unknown(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown detector"):
            self.mod.resolve_selected_detector(self.detectors, "does-not-exist")

    def test_collect_detectors_dedupes_duplicate_arguments_and_preserves_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            detectors_dir = tmp / "detectors"
            fixture_dir = detectors_dir / "test_fixtures"
            fixture_dir.mkdir(parents=True)
            own = fixture_dir / "own_fixture_vuln.sol"
            own.write_text("// fixture\n", encoding="utf-8")

            registry = {
                "own_fixture": {
                    "tier": "A",
                    "verified": True,
                    "engine": "slither",
                    "argument": "own-fixture",
                    "fixture_pair": "",
                },
                "own-fixture": {
                    "tier": "A",
                    "verified": True,
                    "engine": "slither",
                    "argument": "own-fixture",
                    "fixture_pair": "own-fixture",
                },
            }

            with mock.patch.object(self.mod, "REPO_ROOT", tmp), \
                 mock.patch.object(self.mod, "DETECTORS_DIR", detectors_dir):
                rows = self.mod.collect_detectors(registry)

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["argument"], "own-fixture")
        self.assertEqual(row["name"], "own-fixture")
        self.assertEqual(row["own_vuln"], str(own))
        self.assertEqual(row["aliases"], ["own-fixture", "own_fixture"])
        self.assertIs(self.mod.resolve_selected_detector(rows, "own_fixture"), row)
        self.assertIs(self.mod.resolve_selected_detector(rows, "own-fixture"), row)

    def test_bounded_pair_estimate_is_one_detector_times_fixture_count(self) -> None:
        selected = self.mod.resolve_selected_detector(self.detectors, "swap-missing-slippage-protection")
        fixtures = ["a.sol", "b.sol", "c.sol"]
        self.assertEqual(len([selected]) * len(fixtures), 3)

    def test_run_pair_injects_fixture_smoke_mode(self) -> None:
        class FakeCompletedProcess:
            stdout = "[done] total hits: 2\n"
            stderr = ""
            returncode = 0

        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(self.mod.subprocess, "run", return_value=FakeCompletedProcess()) as run_mock:
            result = self.mod._run_pair(
                (
                    "swap-missing-slippage-protection",
                    "swap-missing-slippage-protection",
                    "/tmp/fixture.sol",
                    "python3",
                    5,
                )
            )

        self.assertEqual(result["hit_count"], 2)
        env = run_mock.call_args.kwargs["env"]
        self.assertEqual(env["AUDITOOOR_FIXTURE_SMOKE_MODE"], "1")
        self.assertEqual(os.environ.get("AUDITOOOR_FIXTURE_SMOKE_MODE"), None)

    def test_collect_detectors_resolves_vuln_suffix_without_smoke_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            detectors_dir = tmp / "detectors"
            fixture_dir = detectors_dir / "test_fixtures"
            fixture_dir.mkdir(parents=True)
            own = fixture_dir / "own_fixture_vuln.sol"
            own.write_text("// fixture\n", encoding="utf-8")

            registry = {
                "own-fixture": {
                    "tier": "A",
                    "verified": True,
                    "engine": "slither",
                    "fixture_pair": "own-fixture",
                }
            }

            with mock.patch.object(self.mod, "REPO_ROOT", tmp), \
                 mock.patch.object(self.mod, "DETECTORS_DIR", detectors_dir):
                rows = self.mod.collect_detectors(registry)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["own_vuln"], str(own))

    def test_collect_detectors_still_resolves_vulnerable_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            detectors_dir = tmp / "detectors"
            fixture_dir = detectors_dir / "test_fixtures"
            fixture_dir.mkdir(parents=True)
            own = fixture_dir / "own_fixture_vulnerable.sol"
            own.write_text("// fixture\n", encoding="utf-8")

            registry = {
                "own-fixture": {
                    "tier": "A",
                    "verified": True,
                    "engine": "slither",
                    "fixture_pair": "own-fixture",
                }
            }

            with mock.patch.object(self.mod, "REPO_ROOT", tmp), \
                 mock.patch.object(self.mod, "DETECTORS_DIR", detectors_dir):
                rows = self.mod.collect_detectors(registry)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["own_vuln"], str(own))

    def test_collect_detectors_resolves_nested_positive_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            detectors_dir = tmp / "detectors"
            fixture_dir = detectors_dir / "fixtures" / "own_fixture"
            fixture_dir.mkdir(parents=True)
            own = fixture_dir / "positive.sol"
            own.write_text("// positive\n", encoding="utf-8")
            (fixture_dir / "clean.sol").write_text("// clean\n", encoding="utf-8")

            registry = {
                "own-fixture": {
                    "tier": "A",
                    "verified": True,
                    "engine": "slither",
                    "fixture_pair": "own-fixture",
                }
            }

            with mock.patch.object(self.mod, "REPO_ROOT", tmp), \
                 mock.patch.object(self.mod, "DETECTORS_DIR", detectors_dir):
                rows = self.mod.collect_detectors(registry)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["own_vuln"], str(own))

    def test_collect_fixtures_includes_nested_positive_and_clean_pair(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            detectors_dir = tmp / "detectors"
            fixture_dir = detectors_dir / "fixtures" / "own_fixture"
            fixture_dir.mkdir(parents=True)
            positive = fixture_dir / "positive.sol"
            clean = fixture_dir / "clean.sol"
            ignored = fixture_dir / "helper.sol"
            positive.write_text("// positive\n", encoding="utf-8")
            clean.write_text("// clean\n", encoding="utf-8")
            ignored.write_text("// helper\n", encoding="utf-8")

            with mock.patch.object(self.mod, "REPO_ROOT", tmp), \
                 mock.patch.object(self.mod, "DETECTORS_DIR", detectors_dir):
                fixtures = self.mod.collect_fixtures()

        self.assertEqual(fixtures, [str(positive), str(clean)])

    def test_collect_fixtures_dedupes_hyphen_underscore_nested_mirrors(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            detectors_dir = tmp / "detectors"
            underscore = detectors_dir / "fixtures" / "own_fixture"
            hyphen = detectors_dir / "fixtures" / "own-fixture"
            underscore.mkdir(parents=True)
            hyphen.mkdir(parents=True)
            for fixture_dir in (underscore, hyphen):
                (fixture_dir / "positive.sol").write_text("// positive\n", encoding="utf-8")
                (fixture_dir / "clean.sol").write_text("// clean\n", encoding="utf-8")

            with mock.patch.object(self.mod, "REPO_ROOT", tmp), \
                 mock.patch.object(self.mod, "DETECTORS_DIR", detectors_dir):
                fixtures = self.mod.collect_fixtures()

        self.assertEqual(fixtures, [str(underscore / "positive.sol"), str(underscore / "clean.sol")])

    def test_collect_fixtures_ignores_non_pair_nested_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            detectors_dir = tmp / "detectors"
            fixture_dir = detectors_dir / "fixtures" / "partial_fixture"
            fixture_dir.mkdir(parents=True)
            (fixture_dir / "positive.sol").write_text("// positive only\n", encoding="utf-8")

            with mock.patch.object(self.mod, "REPO_ROOT", tmp), \
                 mock.patch.object(self.mod, "DETECTORS_DIR", detectors_dir):
                fixtures = self.mod.collect_fixtures()

        self.assertEqual(fixtures, [])

    def test_record_pair_hit_counts_tp_on_own_fixture(self) -> None:
        stats_row = {
            "own_vuln": "/tmp/own.sol",
            "tp_count": 0,
            "fp_count": 0,
            "_fp_details": [],
        }

        self.mod._record_pair_hit(stats_row, {"fixture_path": "/tmp/own.sol", "hit_count": 1})

        self.assertEqual(stats_row["tp_count"], 1)
        self.assertEqual(stats_row["fp_count"], 0)
        self.assertEqual(stats_row["_fp_details"], [])

    def test_record_pair_hit_keeps_self_hit_out_of_unintended_fires(self) -> None:
        stats_row = {
            "own_vuln": "/tmp/own.sol",
            "tp_count": 0,
            "fp_count": 0,
            "_fp_details": [],
        }

        self.mod._record_pair_hit(stats_row, {"fixture_path": "/tmp/own.sol", "hit_count": 3})
        self.mod._record_pair_hit(stats_row, {"fixture_path": "/tmp/other.sol", "hit_count": 2})

        self.assertEqual(stats_row["tp_count"], 1)
        self.assertEqual(stats_row["fp_count"], 1)
        self.assertEqual(stats_row["_fp_details"], [{"fixture": "other.sol", "hit_count": 2}])

    def test_build_matrix_includes_self_pair_and_computes_precision(self) -> None:
        own = "/tmp/own.sol"
        other = "/tmp/other.sol"
        detectors = [{
            "name": "swap",
            "argument": "swap",
            "tier": "A",
            "own_vuln": own,
        }]

        class FakeFuture:
            def __init__(self, result):
                self._result = result

            def result(self, timeout=None):
                return self._result

        class FakeExecutor:
            def __init__(self, max_workers):
                self.max_workers = max_workers

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def submit(self, fn, item):
                return FakeFuture(fn(item))

        def fake_wait(submitted, return_when=None, timeout=None):
            return set(submitted), set()

        def fake_run_pair(item):
            det_name, argument, fixture_path, slither_python, timeout_sec = item
            return {
                "detector_name": det_name,
                "argument": argument,
                "fixture_path": fixture_path,
                "hit_count": 1,
                "timed_out": False,
                "errored": False,
                "elapsed": 0.01,
            }

        with mock.patch.object(self.mod, "ProcessPoolExecutor", FakeExecutor), \
             mock.patch.object(self.mod, "wait", side_effect=fake_wait), \
             mock.patch.object(self.mod, "_run_pair", side_effect=fake_run_pair):
            result = self.mod.build_matrix(detectors, [own, other], "python3", workers=1, timeout_sec=5)

        row = result["detectors"]["swap"]
        self.assertEqual(result["meta"]["total_pairs"], 2)
        self.assertEqual(row["total_fixtures_tested"], 2)
        self.assertEqual(row["tp_count"], 1)
        self.assertEqual(row["fp_count"], 1)
        self.assertEqual(row["precision"], 0.5)
        self.assertEqual(row["top_5_unintended_fires"], [{"fixture": "other.sol", "hit_count": 1}])

    def test_build_matrix_counts_tp_when_own_vuln_comes_from_vuln_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            detectors_dir = tmp / "detectors"
            fixture_dir = detectors_dir / "test_fixtures"
            fixture_dir.mkdir(parents=True)
            own = fixture_dir / "own_fixture_vuln.sol"
            other = fixture_dir / "other_fixture_vulnerable.sol"
            own.write_text("// own\n", encoding="utf-8")
            other.write_text("// other\n", encoding="utf-8")
            registry = {
                "own-fixture": {
                    "tier": "A",
                    "verified": True,
                    "engine": "slither",
                    "fixture_pair": "own-fixture",
                }
            }

            class FakeFuture:
                def __init__(self, result):
                    self._result = result

                def result(self, timeout=None):
                    return self._result

            class FakeExecutor:
                def __init__(self, max_workers):
                    self.max_workers = max_workers

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def submit(self, fn, item):
                    return FakeFuture(fn(item))

            def fake_wait(submitted, return_when=None, timeout=None):
                return set(submitted), set()

            def fake_run_pair(item):
                det_name, argument, fixture_path, slither_python, timeout_sec = item
                return {
                    "detector_name": det_name,
                    "argument": argument,
                    "fixture_path": fixture_path,
                    "hit_count": 1,
                    "timed_out": False,
                    "errored": False,
                    "elapsed": 0.01,
                }

            with mock.patch.object(self.mod, "REPO_ROOT", tmp), \
                 mock.patch.object(self.mod, "DETECTORS_DIR", detectors_dir), \
                 mock.patch.object(self.mod, "ProcessPoolExecutor", FakeExecutor), \
                 mock.patch.object(self.mod, "wait", side_effect=fake_wait), \
                 mock.patch.object(self.mod, "_run_pair", side_effect=fake_run_pair):
                detectors = self.mod.collect_detectors(registry)
                result = self.mod.build_matrix(
                    detectors,
                    [str(own), str(other)],
                    "python3",
                    workers=1,
                    timeout_sec=5,
                )

        row = result["detectors"]["own-fixture"]
        self.assertEqual(row["own_vuln"], str(own))
        self.assertEqual(row["tp_count"], 1)
        self.assertEqual(row["fp_count"], 1)
        self.assertEqual(row["precision"], 0.5)
        self.assertEqual(row["top_5_unintended_fires"], [{"fixture": "other_fixture_vulnerable.sol", "hit_count": 1}])

    def test_build_matrix_counts_tp_when_own_vuln_comes_from_nested_positive(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            detectors_dir = tmp / "detectors"
            fixture_dir = detectors_dir / "fixtures" / "own_fixture"
            fixture_dir.mkdir(parents=True)
            own = fixture_dir / "positive.sol"
            clean = fixture_dir / "clean.sol"
            own.write_text("// own\n", encoding="utf-8")
            clean.write_text("// clean\n", encoding="utf-8")
            registry = {
                "own-fixture": {
                    "tier": "A",
                    "verified": True,
                    "engine": "slither",
                    "fixture_pair": "own-fixture",
                }
            }

            class FakeFuture:
                def __init__(self, result):
                    self._result = result

                def result(self, timeout=None):
                    return self._result

            class FakeExecutor:
                def __init__(self, max_workers):
                    self.max_workers = max_workers

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def submit(self, fn, item):
                    return FakeFuture(fn(item))

            def fake_wait(submitted, return_when=None, timeout=None):
                return set(submitted), set()

            def fake_run_pair(item):
                det_name, argument, fixture_path, slither_python, timeout_sec = item
                return {
                    "detector_name": det_name,
                    "argument": argument,
                    "fixture_path": fixture_path,
                    "hit_count": 1,
                    "timed_out": False,
                    "errored": False,
                    "elapsed": 0.01,
                }

            with mock.patch.object(self.mod, "REPO_ROOT", tmp), \
                 mock.patch.object(self.mod, "DETECTORS_DIR", detectors_dir), \
                 mock.patch.object(self.mod, "ProcessPoolExecutor", FakeExecutor), \
                 mock.patch.object(self.mod, "wait", side_effect=fake_wait), \
                 mock.patch.object(self.mod, "_run_pair", side_effect=fake_run_pair):
                detectors = self.mod.collect_detectors(registry)
                result = self.mod.build_matrix(
                    detectors,
                    self.mod.collect_fixtures(),
                    "python3",
                    workers=1,
                    timeout_sec=5,
                )

        row = result["detectors"]["own-fixture"]
        self.assertEqual(row["own_vuln"], str(own))
        self.assertEqual(row["tp_count"], 1)
        self.assertEqual(row["fp_count"], 1)
        self.assertEqual(row["precision"], 0.5)
        self.assertEqual(row["top_5_unintended_fires"], [{"fixture": "clean.sol", "hit_count": 1}])


if __name__ == "__main__":
    unittest.main()
