from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "aurora-delegatecall-inherits-msgvalue-without-eth-transfer"
DETECTOR = ROOT / "detectors" / "wave17" / "aurora_delegatecall_inherits_msgvalue_without_eth_transfer.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "aurora_delegatecall_inherits_msgvalue_without_eth_transfer"
POSITIVE = FIXTURE_DIR / "positive.sol"
RENAMED_POSITIVE = FIXTURE_DIR / "renamed_adapter.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"


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
            probe = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


class AuroraDelegatecallInheritsMsgvalueWithoutEthTransferTest(unittest.TestCase):
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
        self.assertNotIn("UNKNOWN predicate key", proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_and_reference_are_wired_to_supported_predicates(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertNotIn("contract.is_precompile_or_bridge_exit", detector_text)
        self.assertNotIn("precompile|bridge|exit", detector_text)
        self.assertIn("delegatecall", detector_text)
        self.assertIn("callType|DelegateCall", detector_text)
        self.assertIn("callType", detector_text)
        self.assertIn("DelegateCall", detector_text)

        self.assertIn(f"pattern: {PATTERN}", reference_text)
        self.assertNotIn("contract.is_precompile_or_bridge_exit", reference_text)
        self.assertNotIn("precompile|bridge|exit", reference_text)
        self.assertIn("contract.source_matches_regex: '(?i)delegatecall|msg\\.value|callType|DelegateCall'", reference_text)
        self.assertIn("fixtures:", reference_text)

        self.assertIn("function withdrawToNear(address recipient) external payable", positive_text)
        self.assertIn("require(msg.value > 0", positive_text)
        self.assertNotIn("callType != DelegateCall", positive_text)
        self.assertIn("function withdrawToNear(address recipient) external payable", RENAMED_POSITIVE.read_text(encoding="utf-8"))
        self.assertIn("callType != DelegateCall", clean_text)

        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "smoke_pass")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        smoke_text = SMOKE.read_text(encoding="utf-8")
        self.assertNotIn("/opt/homebrew", smoke_text)
        self.assertIn("python3 detectors/run_custom.py", payload["positive_command"])
        self.assertIn("python3 detectors/run_custom.py", payload["clean_command"])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertGreaterEqual(self._hits(RENAMED_POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
