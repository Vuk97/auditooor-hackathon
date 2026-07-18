from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

GRAVEYARD_SMOKE = ROOT / "detectors" / "fixtures" / "division_and_multiplication_operations_finder" / "smoke.json"
LIVE_SMOKE = ROOT / "detectors" / "fixtures" / "perp_glv_cancel_fee_attributed_to_keeper_not_account" / "smoke.json"


def _load_smoke(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _commands(payload: dict[str, object]) -> tuple[str, str]:
    nested = payload.get("commands")
    if isinstance(nested, dict):
        return str(nested.get("positive") or ""), str(nested.get("clean") or "")
    return str(payload.get("positive_command") or ""), str(payload.get("clean_command") or "")


class ScannerWiringBurndownL22EnhanceTests(unittest.TestCase):
    def test_graveyard_detector_path_requires_include_graveyard_and_no_promotion(self) -> None:
        payload = _load_smoke(GRAVEYARD_SMOKE)
        detector_path = str(payload.get("detector_path") or "")
        positive_command, clean_command = _commands(payload)

        self.assertIn("wave_graveyard", detector_path)
        self.assertIn("--include-graveyard", positive_command)
        self.assertIn("--include-graveyard", clean_command)
        self.assertFalse(bool(payload.get("promotion_allowed")))

    def test_live_detector_path_stays_without_include_graveyard_and_no_promotion(self) -> None:
        payload = _load_smoke(LIVE_SMOKE)
        detector_path = str(payload.get("detector_path") or "")
        positive_command, clean_command = _commands(payload)

        self.assertIn("detectors/wave17/", detector_path)
        self.assertNotIn("--include-graveyard", positive_command)
        self.assertNotIn("--include-graveyard", clean_command)
        self.assertFalse(bool(payload.get("promotion_allowed")))


if __name__ == "__main__":
    unittest.main()
