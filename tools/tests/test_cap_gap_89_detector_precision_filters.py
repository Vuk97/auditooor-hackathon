from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
APPLY_QUERIES = ROOT / "tools" / "apply-queries.sh"
SCRIPT_DIR = ROOT / "tools" / "detectors" / "solidity"
FIXTURE_ROOT = ROOT / "detectors" / "fixtures"


class CapGap89DetectorPrecisionTests(unittest.TestCase):
    def _run_script(self, detector: str, fixture_names: list[str]) -> str:
        fixture_dir = FIXTURE_ROOT / detector
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for name in fixture_names:
                shutil.copy(fixture_dir / name, tmp_path / name)
            result = subprocess.run(
                ["python3", str(SCRIPT_DIR / f"{detector}.py"), str(tmp_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

    def _run_apply_queries(self, detector: str, fixture_names: list[str]) -> str:
        fixture_dir = FIXTURE_ROOT / detector
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for name in fixture_names:
                shutil.copy(fixture_dir / name, tmp_path / name)
            result = subprocess.run(
                ["bash", str(APPLY_QUERIES), str(tmp_path), detector],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout + result.stderr

    def test_raw_transfer_positive_shapes_fire(self) -> None:
        out = self._run_script(
            "raw-transfer-no-bool-check",
            ["positive_external_transfer.sol", "positive_transfer_from.sol"],
        )
        self.assertIn("positive_external_transfer.sol", out)
        self.assertIn("positive_transfer_from.sol", out)

    def test_raw_transfer_super_and_erc20_override_shapes_are_clean(self) -> None:
        out = self._run_script(
            "raw-transfer-no-bool-check",
            ["negative_super_transfer.sol", "negative_erc20_override_self_inheritance.sol"],
        )
        self.assertEqual("", out)

    def test_delete_enumerable_positive_layouts_fire(self) -> None:
        out = self._run_script(
            "delete-enumerable-set-struct",
            ["positive_direct_enumerable_layout.sol", "positive_nested_inner_layout.sol"],
        )
        self.assertIn("positive_direct_enumerable_layout.sol", out)
        self.assertIn("positive_nested_inner_layout.sol", out)

    def test_delete_enumerable_plain_mapping_and_simple_struct_are_clean(self) -> None:
        out = self._run_script(
            "delete-enumerable-set-struct",
            ["negative_plain_mapping_mutex.sol", "negative_simple_struct_mapping.sol"],
        )
        self.assertEqual("", out)

    def test_erc4626_missing_pull_positive_shapes_fire(self) -> None:
        out = self._run_script(
            "erc4626-asset-not-pulled",
            ["positive_inline_missing_pull.sol", "positive_helper_missing_pull.sol"],
        )
        self.assertIn("positive_inline_missing_pull.sol", out)
        self.assertIn("positive_helper_missing_pull.sol", out)

    def test_erc4626_helper_pull_and_oz_base_shapes_are_clean(self) -> None:
        out = self._run_script(
            "erc4626-asset-not-pulled",
            ["negative_helper_pulls_asset.sol", "negative_oz_inherited_deposit.sol"],
        )
        self.assertEqual("", out)

    def test_apply_queries_detector_aliases_route_to_precise_filters(self) -> None:
        raw_out = self._run_apply_queries(
            "raw-transfer-no-bool-check",
            ["negative_super_transfer.sol", "negative_erc20_override_self_inheritance.sol"],
        )
        self.assertIn("[CLEAN]", raw_out)
        self.assertNotIn("[HITS]", raw_out)

        delete_out = self._run_apply_queries(
            "delete-enumerable-set-struct",
            ["negative_plain_mapping_mutex.sol", "negative_simple_struct_mapping.sol"],
        )
        self.assertIn("[CLEAN]", delete_out)
        self.assertNotIn("[HITS]", delete_out)

        erc4626_out = self._run_apply_queries(
            "erc4626-asset-not-pulled",
            ["negative_helper_pulls_asset.sol", "negative_oz_inherited_deposit.sol"],
        )
        self.assertIn("[CLEAN]", erc4626_out)
        self.assertNotIn("[HITS]", erc4626_out)


if __name__ == "__main__":
    unittest.main()
