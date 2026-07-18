from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "w69-vault-share-mint-division-before-multiplication"
DETECTOR = ROOT / "detectors" / "wave69" / "w69_vault_share_mint_division_before_multiplication.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "w69_vault_share_mint_division_before_multiplication"

POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
POSITIVE_VARIANT = FIXTURE_DIR / "positive_variant.sol"
CLEAN_VARIANT = FIXTURE_DIR / "clean_variant.sol"
POSITIVE_TRANSFERFROM_INLINE = FIXTURE_DIR / "positive_transferfrom_inline.sol"
CLEAN_TRANSFERFROM_INLINE = FIXTURE_DIR / "clean_transferfrom_inline.sol"


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            proc = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return candidate
    return None


class W69VaultShareMintDivisionBeforeMultiplicationTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_covers_original_and_variant_naming_shapes(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn("depositFor", detector_text)
        self.assertIn("mintAmount", detector_text)
        self.assertIn("recipient", detector_text)
        self.assertIn("transferFrom", detector_text)
        self.assertIn("balanceOf", detector_text)

        positive = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("shares = assets / totalAssets() * totalSupply()", positive)
        self.assertIn("_mint(receiver, shares)", positive)

        positive_variant = POSITIVE_VARIANT.read_text(encoding="utf-8")
        self.assertIn("function depositFor(uint256 depositAmount, address recipient)", positive_variant)
        self.assertIn("mintAmount = depositAmount / totalAssets() * totalSupply()", positive_variant)
        self.assertIn("_mint(recipient, mintAmount)", positive_variant)

        clean_variant = CLEAN_VARIANT.read_text(encoding="utf-8")
        self.assertIn("MathVariant.mulDiv(depositAmount, totalSupply(), totalAssets())", clean_variant)
        self.assertIn("if (mintAmount == 0) revert ZeroShares()", clean_variant)

        positive_transferfrom_inline = POSITIVE_TRANSFERFROM_INLINE.read_text(encoding="utf-8")
        self.assertIn("asset.transferFrom(msg.sender, address(this), assets);", positive_transferfrom_inline)
        self.assertIn("balanceOf[receiver] += shares;", positive_transferfrom_inline)
        self.assertIn("totalShareSupply += shares;", positive_transferfrom_inline)

        clean_transferfrom_inline = CLEAN_TRANSFERFROM_INLINE.read_text(encoding="utf-8")
        self.assertIn("MathInline.mulDiv(assets, totalSupply(), totalAssets())", clean_transferfrom_inline)
        self.assertIn('require(shares > 0, "zero shares");', clean_transferfrom_inline)

    def test_positive_and_variant_fire_while_clean_variants_stay_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)
        self.assertGreaterEqual(self._hits(POSITIVE_VARIANT), 1)
        self.assertEqual(self._hits(CLEAN_VARIANT), 0)
        self.assertGreaterEqual(self._hits(POSITIVE_TRANSFERFROM_INLINE), 1)
        self.assertEqual(self._hits(CLEAN_TRANSFERFROM_INLINE), 0)


if __name__ == "__main__":
    unittest.main()
