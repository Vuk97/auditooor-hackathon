from __future__ import annotations

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
DETECTOR_TO_AC_MAP = ROOT / "reference" / "detector_to_attack_classes_map.yaml"


class GoStateChangeDetectorRankerAliasesTest(unittest.TestCase):
    def test_state_change_detector_ids_route_to_same_class(self) -> None:
        detector_map = yaml.safe_load(DETECTOR_TO_AC_MAP.read_text(encoding="utf-8"))["mappings"]

        expected = {
            "go-cosmos-bank-send-before-module-state-commit": "state-change-between-check-and-use",
            "go_wave1.go-cosmos-bank-send-before-module-state-commit": "state-change-between-check-and-use",
            "go-state-change-between-check-and-use": "state-change-between-check-and-use",
            "go_wave1.go-state-change-between-check-and-use": "state-change-between-check-and-use",
        }

        for detector_id, attack_class in expected.items():
            with self.subTest(detector_id=detector_id):
                self.assertEqual(detector_map[detector_id][0], attack_class)


if __name__ == "__main__":
    unittest.main()
