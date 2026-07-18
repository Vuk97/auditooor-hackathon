from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR = ROOT / "detectors" / "wave19" / "solidity_crosslang_signature_domain_selector_mismatch.py"
REGISTRY = ROOT / "detectors" / "_tier_registry.yaml"
PATTERN = "solidity-crosslang-signature-domain-selector-mismatch"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "solidity_crosslang_signature_domain_selector_mismatch"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"


def _load_detector():
    spec = importlib.util.spec_from_file_location("solidity_crosslang_signature_domain_selector_mismatch", DETECTOR)
    assert spec and spec.loader, f"failed to load {DETECTOR}"
    module = importlib.util.module_from_spec(spec)
    sys.modules["solidity_crosslang_signature_domain_selector_mismatch"] = module
    spec.loader.exec_module(module)
    return module


def _load_registry() -> dict:
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise unittest.SkipTest("PyYAML not installed; cannot validate detector registry") from exc
    return yaml.safe_load(REGISTRY.read_text(encoding="utf-8")) or {}


def _run_runner(fixture: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            str(fixture),
            "--detector",
            PATTERN,
            "--no-manifest",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stdout)
    match = re.search(r"total hits:\s*(\d+)", proc.stdout)
    if match is None:
        raise AssertionError(proc.stdout)
    return int(match.group(1)), proc.stdout


class SolidityCrosslangSignatureDomainSelectorMismatchTest(unittest.TestCase):
    def test_registry_entry_points_at_regex_runner(self) -> None:
        tiers = (_load_registry().get("tiers") or {})
        entry = tiers.get(PATTERN)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["engine"], "regex")
        self.assertEqual(entry["argument"], PATTERN)
        self.assertEqual(entry["runner"], "detectors/run_regex_detectors.py")
        self.assertEqual(
            entry["detector_path"],
            "detectors/wave19/solidity_crosslang_signature_domain_selector_mismatch.py",
        )

    def test_direct_scan_fires_on_positive_and_skips_clean(self) -> None:
        module = _load_detector()
        positive_hits = module.scan(POSITIVE.read_text(encoding="utf-8"), str(POSITIVE))
        clean_hits = module.scan(CLEAN.read_text(encoding="utf-8"), str(CLEAN))

        self.assertEqual(len(positive_hits), 1)
        self.assertEqual(positive_hits[0].detector, PATTERN)
        self.assertEqual(positive_hits[0].severity, "High")
        self.assertEqual(positive_hits[0].function, "_verifyAction")
        self.assertEqual(clean_hits, [])

    def test_smoke_record_matches_fixture_pair_and_detector(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(
            payload["detector_path"],
            "detectors/wave19/solidity_crosslang_signature_domain_selector_mismatch.py",
        )
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["promotion_allowed"])

    def test_regex_runner_positive_and_clean(self) -> None:
        positive_hits, positive_out = _run_runner(POSITIVE)
        clean_hits, clean_out = _run_runner(CLEAN)

        self.assertEqual(positive_hits, 1, positive_out)
        self.assertEqual(clean_hits, 0, clean_out)
        self.assertIn(PATTERN, positive_out)
        self.assertIn(PATTERN, clean_out)


if __name__ == "__main__":
    unittest.main()
