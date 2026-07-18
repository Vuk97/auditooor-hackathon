#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "inventory-smoke-test.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("inventory_smoke_test", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InventorySmokeSelectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_module()

    def test_selector_keeps_only_matching_detector_path(self) -> None:
        paths = [
            self.mod.REPO / "detectors" / "wave1" / "one.py",
            self.mod.REPO / "detectors" / "wave1" / "two.py",
        ]

        def fake_extract(path: Path) -> str | None:
            return {
                paths[0]: "swap-missing-slippage-protection",
                paths[1]: "flashloan-callback-missing-initiator-check",
            }[path]

        selected = self.mod.resolve_selected_detector_paths(paths, "swap-missing-slippage-protection", fake_extract)
        self.assertEqual(selected, [paths[0]])

    def test_selector_rejects_unknown_detector(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown detector"):
            self.mod.resolve_selected_detector_paths([], "does-not-exist", lambda _: None)

    def test_selector_rejects_duplicate_argument(self) -> None:
        paths = [
            self.mod.REPO / "detectors" / "wave1" / "one.py",
            self.mod.REPO / "detectors" / "wave2" / "two.py",
        ]
        with self.assertRaisesRegex(ValueError, "duplicate detector argument"):
            self.mod.resolve_selected_detector_paths(paths, "dup", lambda _: "dup")

    def test_path_selector_keeps_exact_detector_path(self) -> None:
        paths = [
            self.mod.REPO / "detectors" / "wave15" / "one.py",
            self.mod.REPO / "detectors" / "wave17" / "two.py",
        ]

        selected = self.mod.resolve_selected_detector_path(
            paths,
            "detectors/wave17/two.py",
        )
        self.assertEqual(selected, [paths[1]])

    def test_path_selector_rejects_unknown_path(self) -> None:
        paths = [self.mod.REPO / "detectors" / "wave17" / "two.py"]
        with self.assertRaisesRegex(ValueError, "unknown detector path"):
            self.mod.resolve_selected_detector_path(paths, "detectors/wave99/missing.py")

    def test_main_rejects_detector_with_limit(self) -> None:
        with self.assertRaises(SystemExit):
            self.mod.main(["--output-dir", "/tmp/x", "--detector", "x", "--limit", "1"])

    def test_main_rejects_detector_path_with_limit(self) -> None:
        with self.assertRaises(SystemExit):
            self.mod.main(["--output-dir", "/tmp/x", "--detector-path", "x.py", "--limit", "1"])

    def test_main_rejects_detector_argument_and_path_together(self) -> None:
        with self.assertRaises(SystemExit):
            self.mod.main(["--output-dir", "/tmp/x", "--detector", "x", "--detector-path", "x.py"])

    def test_selected_mode_still_writes_standard_outputs(self) -> None:
        detector_path = self.mod.REPO / "detectors" / "wave1" / "swap.py"
        fake_row = {
            "py_path": "detectors/wave1/swap.py",
            "wave": "wave1",
            "argument": "swap-missing-slippage-protection",
            "yaml_status": "live",
            "vuln_fixture": "patterns/fixtures/swap-missing-slippage-protection_vuln.sol",
            "clean_fixture": "patterns/fixtures/swap-missing-slippage-protection_clean.sol",
            "vuln_hits": 1,
            "clean_hits": 0,
            "status": "smoke_pass",
            "notes": "",
        }
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(self.mod, "discover_detectors", return_value=[detector_path]), \
                 mock.patch.object(self.mod, "extract_argument", return_value="swap-missing-slippage-protection"), \
                 mock.patch.object(self.mod, "smoke_one", return_value=fake_row):
                rc = self.mod.main(["--output-dir", tmp, "--detector", "swap-missing-slippage-protection", "--workers", "1"])

            self.assertEqual(rc, 0)
            out_dir = Path(tmp)
            summary = json.loads((out_dir / "inventory_smoke_summary.json").read_text())
            promote = json.loads((out_dir / "inventory_smoke_promote_queue.json").read_text())
            passing = (out_dir / "inventory_smoke_passing.txt").read_text()

            self.assertEqual(summary["total_detectors_scanned"], 1)
            self.assertEqual(len(summary["results"]), 1)
            self.assertEqual(len(promote), 1)
            self.assertIn("swap-missing-slippage-protection", passing)

    def test_selected_path_mode_still_writes_standard_outputs(self) -> None:
        detector_path = self.mod.REPO / "detectors" / "wave17" / "rank22.py"
        fake_row = {
            "py_path": "detectors/wave17/rank22.py",
            "wave": "wave17",
            "argument": "a-denial-of-ervice-attack-can-obstruct-flop-auctions",
            "yaml_status": "live",
            "vuln_fixture": "detectors/test_fixtures/a_denial_of_ervice_attack_can_obstruct_flop_auctions_vulnerable.sol",
            "clean_fixture": "detectors/test_fixtures/a_denial_of_ervice_attack_can_obstruct_flop_auctions_clean.sol",
            "vuln_hits": 1,
            "clean_hits": 0,
            "status": "smoke_pass",
            "notes": "",
        }
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(self.mod, "discover_detectors", return_value=[detector_path]), \
                 mock.patch.object(self.mod, "smoke_one", return_value=fake_row):
                rc = self.mod.main(["--output-dir", tmp, "--detector-path", str(detector_path), "--workers", "1"])

            self.assertEqual(rc, 0)
            out_dir = Path(tmp)
            summary = json.loads((out_dir / "inventory_smoke_summary.json").read_text())
            promote = json.loads((out_dir / "inventory_smoke_promote_queue.json").read_text())
            passing = (out_dir / "inventory_smoke_passing.txt").read_text()

            self.assertEqual(summary["total_detectors_scanned"], 1)
            self.assertEqual(len(summary["results"]), 1)
            self.assertEqual(len(promote), 1)
            self.assertIn("a-denial-of-ervice-attack-can-obstruct-flop-auctions", passing)

    def test_discover_detectors_includes_nested_graveyard_paths_when_requested(self) -> None:
        graveyard_path = (
            self.mod.REPO
            / "detectors"
            / "wave_graveyard"
            / "wave14_broken"
            / "unsafe_random_function.py"
        )
        if not graveyard_path.is_file():
            self.skipTest("real graveyard detector fixture missing")
        without_graveyard = self.mod.discover_detectors(include_graveyard=False)
        with_graveyard = self.mod.discover_detectors(include_graveyard=True)
        self.assertNotIn(graveyard_path, without_graveyard)
        self.assertIn(graveyard_path, with_graveyard)

    def test_find_fixtures_supports_wave14_broken_fixture_pairs(self) -> None:
        vuln, clean = self.mod.find_fixtures("unsafe-random-function")
        self.assertEqual(
            vuln,
            self.mod.REPO / "detectors" / "wave14_broken" / "unsafe_random_function_vulnerable.sol",
        )
        self.assertEqual(
            clean,
            self.mod.REPO / "detectors" / "wave14_broken" / "unsafe_random_function_clean.sol",
        )

    def test_metadata_fixture_pair_supports_detector_fixture_smoke_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_dir = root / "detectors" / "fixtures" / "reward_mint_uses_spot_pool_ratio_no_flashloan_guard"
            fixture_dir.mkdir(parents=True)
            positive = fixture_dir / "positive.sol"
            clean = fixture_dir / "clean.sol"
            positive.write_text("contract Positive {}\n", encoding="utf-8")
            clean.write_text("contract Clean {}\n", encoding="utf-8")
            (fixture_dir / "smoke.json").write_text(
                json.dumps(
                    {
                        "pattern": "reward-mint-uses-spot-pool-ratio-no-flashloan-guard",
                        "detector_path": "detectors/wave17/reward_mint_uses_spot_pool_ratio_no_flashloan_guard.py",
                        "positive_fixture_path": str(positive.relative_to(root)),
                        "clean_fixture_path": str(clean.relative_to(root)),
                    }
                ),
                encoding="utf-8",
            )

            vuln, fixed = self.mod._metadata_fixture_pair(
                "reward-mint-uses-spot-pool-ratio-no-flashloan-guard",
                root,
            )

        self.assertEqual(vuln, positive)
        self.assertEqual(fixed, clean)

    def test_metadata_fixture_pair_rejects_cross_detector_smoke_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_dir = root / "detectors" / "fixtures" / "reward_mint_uses_spot_pool_ratio_no_flashloan_guard"
            fixture_dir.mkdir(parents=True)
            positive = fixture_dir / "positive.sol"
            clean = fixture_dir / "clean.sol"
            positive.write_text("contract Positive {}\n", encoding="utf-8")
            clean.write_text("contract Clean {}\n", encoding="utf-8")
            (fixture_dir / "smoke.json").write_text(
                json.dumps(
                    {
                        "pattern": "other-detector",
                        "detector_path": "detectors/wave17/other_detector.py",
                        "positive_fixture_path": str(positive.relative_to(root)),
                        "clean_fixture_path": str(clean.relative_to(root)),
                    }
                ),
                encoding="utf-8",
            )

            vuln, fixed = self.mod._metadata_fixture_pair(
                "reward-mint-uses-spot-pool-ratio-no-flashloan-guard",
                root,
            )

        self.assertIsNone(vuln)
        self.assertIsNone(fixed)

    def test_metadata_fixture_pair_rejects_partial_binding_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_dir = root / "detectors" / "fixtures" / "reward_mint_uses_spot_pool_ratio_no_flashloan_guard"
            fixture_dir.mkdir(parents=True)
            positive = fixture_dir / "positive.sol"
            clean = fixture_dir / "clean.sol"
            positive.write_text("contract Positive {}\n", encoding="utf-8")
            clean.write_text("contract Clean {}\n", encoding="utf-8")
            (fixture_dir / "smoke.json").write_text(
                json.dumps(
                    {
                        "pattern": "reward-mint-uses-spot-pool-ratio-no-flashloan-guard",
                        "detector_path": "detectors/wave17/other_detector.py",
                        "positive_fixture_path": str(positive.relative_to(root)),
                        "clean_fixture_path": str(clean.relative_to(root)),
                    }
                ),
                encoding="utf-8",
            )

            vuln, fixed = self.mod._metadata_fixture_pair(
                "reward-mint-uses-spot-pool-ratio-no-flashloan-guard",
                root,
            )

        self.assertIsNone(vuln)
        self.assertIsNone(fixed)

    def test_python_candidates_prefer_auditooor_env_then_slither_env(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "AUDITOOOR_PYTHON_SLITHER": "/tmp/auditooor-python",
                "SLITHER_PYTHON": "/tmp/slither-python",
            },
            clear=False,
        ), mock.patch.object(self.mod.shutil, "which", return_value=None):
            candidates = self.mod._python_candidates()

        self.assertEqual(candidates[:2], ["/tmp/auditooor-python", "/tmp/slither-python"])

    def test_slither_python_selects_first_candidate_with_required_modules(self) -> None:
        def fake_imports(python_bin: str, module: str) -> bool:
            return python_bin == "/tmp/good-python" and module in {
                "slither",
                "slither.detectors.abstract_detector",
            }

        with mock.patch.object(self.mod, "_python_candidates", return_value=["/tmp/bad-python", "/tmp/good-python"]), \
             mock.patch.object(self.mod, "_python_imports_module", side_effect=fake_imports):
            self.assertEqual(self.mod._slither_python(), "/tmp/good-python")

    def test_smoke_metadata_uses_portable_python3_and_graveyard_command_shape(self) -> None:
        graveyard_detector = (
            self.mod.REPO
            / "detectors"
            / "wave_graveyard"
            / "wave14_broken"
            / "unsafe_random_function.py"
        )
        vuln = (
            self.mod.REPO
            / "detectors"
            / "wave14_broken"
            / "unsafe_random_function_vulnerable.sol"
        )
        clean = (
            self.mod.REPO
            / "detectors"
            / "wave14_broken"
            / "unsafe_random_function_clean.sol"
        )

        with mock.patch.object(
            self.mod,
            "_python_candidates",
            return_value=["/opt/homebrew/opt/python@3.13/bin/python3.13", "/tmp/slither-python"],
        ):
            payload = self.mod._smoke_metadata(
                graveyard_detector,
                "unsafe-random-function",
                vuln,
                clean,
            )

        self.assertEqual(payload["runner_python"], "python3")
        self.assertIn("python3 detectors/run_custom.py", payload["positive_command"])
        self.assertIn("python3 detectors/run_custom.py", payload["clean_command"])
        self.assertIn("--include-graveyard", payload["positive_command"])
        self.assertIn("--include-graveyard", payload["clean_command"])
        self.assertNotIn("/opt/homebrew/opt/python@3.13/bin/python3.13", payload["positive_command"])
        self.assertNotIn("/opt/homebrew/opt/python@3.13/bin/python3.13", payload["clean_command"])

    def test_run_smoke_reports_missing_slither_without_running_detector(self) -> None:
        fixture = self.mod.REPO / "detectors" / "wave14_broken" / "unsafe_random_function_vulnerable.sol"

        with mock.patch.object(self.mod, "_slither_python", return_value=""), \
             mock.patch.object(self.mod.subprocess, "run") as run_mock:
            hits, note = self.mod.run_smoke("unsafe-random-function", fixture)

        self.assertEqual(hits, -1)
        self.assertIn("MISSING_SLITHER_ANALYZER", note)
        run_mock.assert_not_called()

    def test_run_smoke_can_forward_include_graveyard_flag(self) -> None:
        fixture = self.mod.REPO / "detectors" / "wave14_broken" / "unsafe_random_function_vulnerable.sol"

        class FakeCompletedProcess:
            def __init__(self) -> None:
                self.stdout = "[done] total hits: 1\n"
                self.stderr = ""

        with mock.patch.object(self.mod, "_slither_python", return_value="/tmp/slither-python"), \
             mock.patch.object(self.mod.subprocess, "run", return_value=FakeCompletedProcess()) as run_mock:
            hits, note = self.mod.run_smoke(
                "unsafe-random-function",
                fixture,
                include_graveyard=True,
            )

        self.assertEqual(hits, 1)
        self.assertEqual(note, "")
        cmd = run_mock.call_args.args[0]
        self.assertEqual(cmd[0], "/tmp/slither-python")
        self.assertIn("--include-graveyard", cmd)


if __name__ == "__main__":
    unittest.main()
