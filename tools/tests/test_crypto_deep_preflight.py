#!/usr/bin/env python3
"""V5-P0-09 / Gap 19 regression tests for `tools/crypto-deep-runner.py`.

Asserts the in-scope-surface preflight introduced for V5-P0-09:

  1. A non-verifier workspace returns SKIP/advisory (single line, exit 0,
     no 161KB OPEN-noise report).
  2. A verifier-fixture workspace still emits crypto candidates.
  3. `--force` overrides the auto-skip even when the workspace has zero
     verifier surface.
  4. Vendored verifier files under `lib/` do NOT trigger the preflight
     (Codex's plan: "must not treat vendored library verifier names as a
     target surface unless explicitly requested").
  5. Test/mock paths are also ignored by the preflight.

Hermetic. Stdlib-only. Uses the script via subprocess.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "crypto-deep-runner.py"
TEMPLATE = ROOT / "templates" / "crypto_verifier_review.md"


_TOY_VERIFIER = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ToyVerifier {
    function verify(bytes calldata proof) external pure returns (bool) {
        return proof.length > 0;
    }
}
"""

_PLAIN_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PlainBank {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
}
"""


def _run(*args: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


class CryptoDeepPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        (self.ws / "src").mkdir()
        self.packet = self.ws / "packet.json"
        self.report = self.ws / "report.md"
        self.assertTrue(TEMPLATE.exists())

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # --- 1 -------------------------------------------------------------------
    def test_no_verifier_workspace_skips(self) -> None:
        (self.ws / "src" / "PlainBank.sol").write_text(_PLAIN_CONTRACT)
        rc, _, stderr = _run(
            "--phase", "all",
            "--workspace", str(self.ws),
            "--root", str(self.ws / "src"),
            "--template", str(TEMPLATE),
            "--packet-out", str(self.packet),
            "--report-out", str(self.report),
        )
        self.assertEqual(rc, 0, msg=stderr)
        self.assertIn("crypto-deep: SKIPPED", stderr)
        self.assertIn("no verifier surface", stderr)
        # Report exists but is the tiny SKIPPED report, not the 161KB
        # OPEN-noise from the prior bug. < 4KB is generous.
        self.assertTrue(self.report.exists())
        self.assertLess(self.report.stat().st_size, 4096,
                        "skipped report must be small advisory note")
        # Packet records the skip cleanly.
        packet = json.loads(self.packet.read_text())
        self.assertTrue(packet.get("skipped"))
        self.assertEqual(packet.get("skip_reason"), "no_inscope_verifier_surface")
        self.assertEqual(packet.get("verifier_contracts"), [])

    # --- 2 -------------------------------------------------------------------
    def test_verifier_workspace_still_emits_candidates(self) -> None:
        (self.ws / "src" / "ToyVerifier.sol").write_text(_TOY_VERIFIER)
        rc, _, _ = _run(
            "--phase", "all",
            "--workspace", str(self.ws),
            "--root", str(self.ws / "src"),
            "--template", str(TEMPLATE),
            "--packet-out", str(self.packet),
            "--report-out", str(self.report),
        )
        self.assertEqual(rc, 0)
        packet = json.loads(self.packet.read_text())
        # NOT skipped — has surface.
        self.assertNotIn("skipped", packet)
        self.assertEqual(len(packet["verifier_contracts"]), 1)
        self.assertIn("ToyVerifier", packet["verifier_contracts"][0]["contracts"])

    # --- 3 -------------------------------------------------------------------
    def test_force_flag_overrides_skip(self) -> None:
        (self.ws / "src" / "PlainBank.sol").write_text(_PLAIN_CONTRACT)
        rc, _, _ = _run(
            "--phase", "all",
            "--workspace", str(self.ws),
            "--root", str(self.ws / "src"),
            "--template", str(TEMPLATE),
            "--packet-out", str(self.packet),
            "--report-out", str(self.report),
            "--force",
        )
        self.assertEqual(rc, 0)
        packet = json.loads(self.packet.read_text())
        # NOT skipped under --force; runner did the actual scan and found
        # zero candidates (PlainBank has no verifier shape).
        self.assertNotIn("skipped", packet)
        self.assertEqual(packet["verifier_contracts"], [])
        # Report is the regular emit-phase report (NOT the SKIPPED note).
        self.assertNotIn("crypto-deep — SKIPPED", self.report.read_text())

    # --- 4 -------------------------------------------------------------------
    def test_vendored_verifier_in_lib_does_not_trigger_preflight(self) -> None:
        # Plain in-scope code under src/ ...
        (self.ws / "src" / "PlainBank.sol").write_text(_PLAIN_CONTRACT)
        # ... and a vendored verifier under lib/ that should NOT count.
        vendored_dir = self.ws / "lib" / "openzeppelin" / "contracts" / "utils" / "cryptography"
        vendored_dir.mkdir(parents=True)
        (vendored_dir / "Verifier.sol").write_text(_TOY_VERIFIER)

        rc, _, stderr = _run(
            "--phase", "all",
            "--workspace", str(self.ws),
            "--root", str(self.ws / "src"),
            "--template", str(TEMPLATE),
            "--packet-out", str(self.packet),
            "--report-out", str(self.report),
        )
        self.assertEqual(rc, 0)
        # Preflight should still SKIP because nothing in src/ has surface.
        self.assertIn("crypto-deep: SKIPPED", stderr)
        packet = json.loads(self.packet.read_text())
        self.assertTrue(packet.get("skipped"))

    # --- 5 -------------------------------------------------------------------
    def test_test_and_mock_paths_ignored_by_preflight(self) -> None:
        (self.ws / "src" / "PlainBank.sol").write_text(_PLAIN_CONTRACT)
        # Verifier shapes under test/ and mock/ should NOT trigger the
        # preflight either.
        (self.ws / "test").mkdir()
        (self.ws / "test" / "VerifierTest.sol").write_text(_TOY_VERIFIER)
        (self.ws / "mock").mkdir()
        (self.ws / "mock" / "MockVerifier.sol").write_text(_TOY_VERIFIER)

        rc, _, stderr = _run(
            "--phase", "all",
            "--workspace", str(self.ws),
            "--root", str(self.ws / "src"),
            "--template", str(TEMPLATE),
            "--packet-out", str(self.packet),
            "--report-out", str(self.report),
        )
        self.assertEqual(rc, 0)
        self.assertIn("crypto-deep: SKIPPED", stderr)


if __name__ == "__main__":
    unittest.main()
