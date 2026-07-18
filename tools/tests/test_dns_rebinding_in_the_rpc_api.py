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
PATTERN = "dns-rebinding-in-the-rpc-api"
DETECTOR = ROOT / "detectors" / "wave_graveyard" / "wave14_broken" / "dns_rebinding_in_the_rpc_api.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "dns_rebinding_in_the_rpc_api"
POSITIVE = FIXTURE_DIR / "ssi-fix-057_positive.sol"
CLEAN = FIXTURE_DIR / "ssi-fix-057_clean.sol"
MANIFEST = FIXTURE_DIR / "ssi-fix-057_manifest.json"
SMOKE = FIXTURE_DIR / "ssi-fix-057_smoke.json"
SNIPPET = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "wave14_broken"
    / "dns_rebinding_in_the_rpc_api.test.snippet"
)


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


class DnsRebindingInTheRpcApiTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [
                slither_python,
                str(RUNNER),
                "--include-graveyard",
                "--tier=ALL",
                str(fixture),
                PATTERN,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_compiles_after_string_fix(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_manifest_and_snippet_record_proxy_fixture_pair(self) -> None:
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertTrue(payload["advisory_only"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["detector_path"], str(DETECTOR.relative_to(ROOT)))
        self.assertEqual(payload["positive_fixture_path"], str(POSITIVE.relative_to(ROOT)))
        self.assertEqual(payload["clean_fixture_path"], str(CLEAN.relative_to(ROOT)))
        self.assertIn("proxy only", payload["operator_note"])
        self.assertIn("does not prove DNS rebinding", payload["operator_note"])

        snippet = SNIPPET.read_text(encoding="utf-8")
        self.assertIn('"ssi-fix-057_positive.sol"', snippet)
        self.assertIn('"ssi-fix-057_clean.sol"', snippet)

    def test_smoke_record_keeps_not_submit_ready_proxy_posture(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["promotion_allowed"])
        self.assertIn("--include-graveyard", payload["positive_command"])
        self.assertIn("proxy detector", payload["limitation_note"])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
