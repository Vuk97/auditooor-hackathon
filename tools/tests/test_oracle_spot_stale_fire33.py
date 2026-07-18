from __future__ import annotations

import importlib.util
import json
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "wave17" / "oracle_spot_stale_fire33.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "oracle_spot_stale_fire33.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "oracle_spot_stale_fire33.sol"
)
PATTERN = "oracle-spot-stale-fire33"


def _load_detector():
    module_name = "oracle_spot_stale_fire33"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class OracleSpotStaleFire33Test(unittest.TestCase):
    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR)
        self.assertIn(f'DETECTOR_NAME = "{PATTERN}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn('VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"', detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("oracle-price-manipulation", detector_text)
        self.assertIn("reports/detector_lift_fire32_20260605/post_priorities_all.md", detector_text)
        self.assertIn("oracle-atomic-front-run-manipulation.yaml", detector_text)
        self.assertIn("ec-stale-oracle-no-freshness-check.yaml", detector_text)
        self.assertIn("ec-spot-price-used-as-oracle.yaml", detector_text)
        self.assertIn("oracle-staleness-not-checked.yaml", detector_text)

    def test_fixture_text_covers_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("function mintAgainstLatestAnswer", positive)
        self.assertIn("priceFeed.latestAnswer()", positive)
        self.assertIn("function liquidateWithStaleRoundData", positive)
        self.assertIn("priceFeed.latestRoundData()", positive)
        self.assertIn("function settleUsingPoolSpot", positive)
        self.assertIn("pair.getReserves()", positive)
        self.assertIn("uint256 price = uint256(reserve1) * 1e18 / uint256(reserve0);", positive)
        self.assertNotIn("HEARTBEAT", positive)
        self.assertNotIn("GRACE_PERIOD", positive)
        self.assertNotIn("consult", positive)

        self.assertIn("sequencerUptimeFeed.latestRoundData()", negative)
        self.assertIn("block.timestamp - updatedAt <= HEARTBEAT", negative)
        self.assertIn("answeredInRound >= roundId", negative)
        self.assertIn("twapOracle.consult", negative)
        self.assertIn("require(reserve0 > 0 && reserve1 > 0", negative)
        self.assertIn("price < 10_000e18", negative)

    def test_direct_scan_positive_fires_and_negative_is_silent(self) -> None:
        detector = _load_detector()
        positive_hits = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_hits = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(negative_hits, [])
        self.assertEqual({hit.detector for hit in positive_hits}, {PATTERN})
        self.assertEqual({hit.severity for hit in positive_hits}, {"High"})
        self.assertEqual(
            {hit.function for hit in positive_hits},
            {
                "mintAgainstLatestAnswer",
                "liquidateWithStaleRoundData",
                "settleUsingPoolSpot",
            },
        )

        messages = "\n".join(hit.message for hit in positive_hits)
        self.assertIn("single latest oracle answer", messages)
        self.assertIn("single AMM or pool spot price", messages)
        self.assertIn("heartbeat or updatedAt freshness check", messages)
        self.assertIn("sequencer grace window", messages)
        self.assertIn("TWAP window", messages)
        self.assertIn("confidence bound", messages)
        self.assertIn("denominator guard", messages)
        self.assertIn("outlier guard", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_regex_runner_reports_positive_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oracle_spot_stale_fire33_") as tmp:
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

            self.assertEqual(positive_data["per_detector_counts"][PATTERN], 3)
            self.assertEqual(negative_data["per_detector_counts"][PATTERN], 0)
            self.assertEqual(negative_data["findings"], [])
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )
            self.assertEqual(
                {row["function"] for row in positive_data["findings"]},
                {
                    "mintAgainstLatestAnswer",
                    "liquidateWithStaleRoundData",
                    "settleUsingPoolSpot",
                },
            )


if __name__ == "__main__":
    unittest.main()
