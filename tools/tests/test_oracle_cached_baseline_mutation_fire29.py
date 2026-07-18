from __future__ import annotations

import importlib.util
import json
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "wave17" / "oracle_cached_baseline_mutation_fire29.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "oracle_cached_baseline_mutation_fire29.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "oracle_cached_baseline_mutation_fire29.sol"
)
PATTERN = "oracle-cached-baseline-mutation-fire29"


def _load_detector():
    module_name = "oracle_cached_baseline_mutation_fire29"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class OracleCachedBaselineMutationFire29Test(unittest.TestCase):
    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        detector_text = DETECTOR.read_text(encoding="utf-8")

        self.assertIn(f'DETECTOR_NAME = "{PATTERN}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("oracle-config-changes-do-not-invalidate-cached-prices.yaml", detector_text)
        self.assertIn("stale-price-cache-bypasses-oracle-config-changes.yaml", detector_text)
        self.assertIn("cached-oracle-prices-ignore-per-asset-freshness-limits.yaml", detector_text)
        self.assertIn("oracle-price-manipulation", detector_text)
        self.assertIn("same-entrypoint-cache-reset-before-check", detector_text)
        self.assertIn("same-transaction-helper-baseline-reset-before-check", detector_text)
        self.assertIn("same-entrypoint-cache-overwrite-after-check", detector_text)

    def test_fixture_text_covers_positive_and_negative_boundaries(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("cachedReferencePrice[asset] = currentPrice;", positive)
        self.assertIn("cachedAt[asset] = block.timestamp;", positive)
        self.assertIn("_refreshBaseline(asset, currentPrice);", positive)
        self.assertIn("currentPrice <= cachedReferencePrice[asset] * (BPS + maxDeviationBps) / BPS", positive)
        self.assertIn("cachedReferencePrice[asset] = currentPrice;", positive)

        self.assertIn("external onlyOwner", negative)
        self.assertIn("external view returns", negative)
        self.assertIn("external onlyKeeper", negative)
        self.assertIn("delete cachedReferencePrice[asset];", negative)
        self.assertIn("require(_withinDeviation(currentPrice, previousPrice, maxDeviationBps)", negative)

    def test_direct_scan_positive_fires_and_negative_is_silent(self) -> None:
        detector = _load_detector()
        positive_hits = detector.scan(POSITIVE.read_text(encoding="utf-8"), str(POSITIVE))
        negative_hits = detector.scan(NEGATIVE.read_text(encoding="utf-8"), str(NEGATIVE))

        self.assertEqual(len(positive_hits), 5)
        self.assertEqual(negative_hits, [])
        self.assertEqual({hit.detector for hit in positive_hits}, {PATTERN})
        self.assertEqual({hit.severity for hit in positive_hits}, {"High"})

        messages = "\n".join(hit.message for hit in positive_hits)
        self.assertIn("same-entrypoint-cache-reset-before-check", messages)
        self.assertIn("same-transaction-helper-baseline-reset-before-check", messages)
        self.assertIn("same-entrypoint-cache-overwrite-after-check", messages)
        self.assertIn("cachedReferencePrice", messages)
        self.assertIn("cachedAt", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

        self.assertEqual(
            {hit.function for hit in positive_hits},
            {
                "borrowWithCallerResetBaseline",
                "swapAfterTimestampOverwrite",
                "mintViaRefreshHelper",
                "redeemAndRollBaseline",
            },
        )

    def test_regex_runner_positive_fixture_fires_and_negative_stays_quiet(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oracle_cached_baseline_fire29_") as tmp:
            positive_manifest = Path(tmp) / "positive.json"
            negative_manifest = Path(tmp) / "negative.json"

            positive_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(POSITIVE),
                    "--detector",
                    PATTERN,
                    "--output",
                    str(positive_manifest),
                    "--workspace",
                    str(ROOT),
                    "--json-only",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
            )
            self.assertEqual(positive_proc.returncode, 0, positive_proc.stdout)

            negative_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(NEGATIVE),
                    "--detector",
                    PATTERN,
                    "--output",
                    str(negative_manifest),
                    "--workspace",
                    str(ROOT),
                    "--json-only",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
            )
            self.assertEqual(negative_proc.returncode, 0, negative_proc.stdout)

            positive_data = json.loads(positive_manifest.read_text(encoding="utf-8"))
            negative_data = json.loads(negative_manifest.read_text(encoding="utf-8"))

            self.assertEqual(positive_data["per_detector_counts"][PATTERN], 5)
            self.assertEqual(negative_data["per_detector_counts"][PATTERN], 0)
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
