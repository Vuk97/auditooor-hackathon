#!/usr/bin/env python3
"""Tests for tools/crypto-deep-runner.py - V4 P3 crypto deep profile.

Hermetic: every test builds a throwaway directory tree with synthetic .sol
files, runs the runner as a subprocess, and asserts on the JSON packet
schema and the rendered Markdown report.

Coverage map (V4 Section 2 Workstream C2 + Section 4 P3 acceptance):

  detect phase
    - test_detector_finds_verifier        ToyVerifier in fixture root  -> 1 candidate
    - test_detector_ignores_plain_lib     SafeMath alone               -> 0 candidates
    - test_detector_flags_proof_import    `import "gnark/..."`         -> 1 candidate (OOS)
    - test_work_packet_schema             schema_version + keys present

  emit phase
    - test_report_classifies_open                ToyVerifier missing markers  -> OPEN row
    - test_report_classifies_defense_in_depth    Plonk-named with markers    -> DEFENSE_IN_DEPTH_ONLY row
    - test_report_classifies_oos_dependent       proof-import-only file       -> OOS_DEPENDENT row

The test count (7) is intentional - matches the "5-7 tests" target in the V4
P3 spec deliverables list.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "crypto-deep-runner.py"
TEMPLATE = ROOT / "templates" / "crypto_verifier_review.md"


# Synthetic Solidity sources used by the tests. Kept as constants here
# rather than importing the real fixture so that test isolation stays
# tight and we can craft variants (Plonk-named, proof-import-only, etc.)
# without touching the canonical fixture.

_TOY_VERIFIER = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ToyVerifier {
    function verify(bytes calldata proof) external pure returns (bool) {
        return proof.length > 0;
    }
}
"""

_SAFE_MATH = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}
"""

_PLONK_VERIFIER_WITH_MARKERS = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PlonkVerifier {
    bytes32 public DOMAIN_SEPARATOR;
    uint256 public constant CHAIN_ID = block.chainid;
    bytes32 public verifyingKey;
    mapping(bytes32 => bool) public usedProof;

    function verify(bytes calldata proof) external view returns (bool) {
        require(proof.length > 0, "InvalidProof");
        return true;
    }
}
"""

_PROOF_IMPORT_ONLY = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "gnark/bn128.sol";

contract Wrapper {
    function noop() external pure returns (uint256) { return 1; }
}
"""


def _run(*args: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


class CryptoDeepProfileTests(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.scan_root = self.tmp / "contracts"
        self.scan_root.mkdir()
        self.packet = self.tmp / "packet.json"
        self.report = self.tmp / "report.md"
        # The template lives at the canonical repo path; this test must be
        # runnable from the repo root.
        self.assertTrue(TEMPLATE.exists(), f"template missing: {TEMPLATE}")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # ---- detect-phase tests ------------------------------------------------

    def test_detector_finds_verifier(self) -> None:
        (self.scan_root / "ToyVerifier.sol").write_text(_TOY_VERIFIER)
        rc, _, _ = _run(
            "--phase", "detect",
            "--root", str(self.scan_root),
            "--packet-out", str(self.packet),
        )
        self.assertEqual(rc, 0)
        data = json.loads(self.packet.read_text())
        self.assertEqual(len(data["verifier_contracts"]), 1)
        self.assertIn("ToyVerifier", data["verifier_contracts"][0]["contracts"])

    def test_detector_ignores_plain_lib(self) -> None:
        (self.scan_root / "SafeMath.sol").write_text(_SAFE_MATH)
        rc, _, _ = _run(
            "--phase", "detect",
            "--root", str(self.scan_root),
            "--packet-out", str(self.packet),
            # V5-P0-09: --force bypasses the in-scope-surface preflight,
            # which would otherwise skip a SafeMath-only workspace and
            # never invoke the underlying detector. The original test
            # intent is to assert detect-phase behavior on a plain
            # library, so we keep that scope by forcing.
            "--force",
        )
        self.assertEqual(rc, 0)
        data = json.loads(self.packet.read_text())
        self.assertEqual(data["verifier_contracts"], [])
        self.assertGreaterEqual(data["files_scanned"], 1)

    def test_detector_flags_proof_import(self) -> None:
        (self.scan_root / "Wrapper.sol").write_text(_PROOF_IMPORT_ONLY)
        rc, _, _ = _run(
            "--phase", "detect",
            "--root", str(self.scan_root),
            "--packet-out", str(self.packet),
        )
        self.assertEqual(rc, 0)
        data = json.loads(self.packet.read_text())
        self.assertEqual(len(data["verifier_contracts"]), 1)
        item = data["verifier_contracts"][0]
        self.assertTrue(item["has_proof_import"])
        self.assertEqual(item["contracts"], [])

    def test_work_packet_schema(self) -> None:
        (self.scan_root / "ToyVerifier.sol").write_text(_TOY_VERIFIER)
        rc, _, _ = _run(
            "--phase", "detect",
            "--root", str(self.scan_root),
            "--packet-out", str(self.packet),
        )
        self.assertEqual(rc, 0)
        data = json.loads(self.packet.read_text())
        # Top-level schema keys
        for key in ("schema_version", "root", "files_scanned", "verifier_contracts"):
            self.assertIn(key, data)
        self.assertEqual(data["schema_version"], 1)
        # Per-candidate schema keys
        item = data["verifier_contracts"][0]
        for key in ("file", "contracts", "imports", "has_proof_import", "markers"):
            self.assertIn(key, item)

    # ---- emit-phase tests --------------------------------------------------

    def test_report_classifies_open(self) -> None:
        (self.scan_root / "ToyVerifier.sol").write_text(_TOY_VERIFIER)
        rc, _, _ = _run(
            "--phase", "all",
            "--root", str(self.scan_root),
            "--template", str(TEMPLATE),
            "--packet-out", str(self.packet),
            "--report-out", str(self.report),
        )
        self.assertEqual(rc, 0, msg=self.report)
        text = self.report.read_text()
        # ToyVerifier has zero markers - Domain Separation row must be OPEN.
        self.assertRegex(text, r"\| Domain Separation \| OPEN \|")

    def test_report_classifies_defense_in_depth(self) -> None:
        (self.scan_root / "PlonkVerifier.sol").write_text(_PLONK_VERIFIER_WITH_MARKERS)
        rc, _, _ = _run(
            "--phase", "all",
            "--root", str(self.scan_root),
            "--template", str(TEMPLATE),
            "--packet-out", str(self.packet),
            "--report-out", str(self.report),
        )
        self.assertEqual(rc, 0, msg=self.report)
        text = self.report.read_text()
        # PlonkVerifier carries domain_separator + chain_id + vk_binding markers.
        self.assertRegex(text, r"\| Domain Separation \| DEFENSE_IN_DEPTH_ONLY \|")
        self.assertRegex(text, r"\| Chain-ID Binding \| DEFENSE_IN_DEPTH_ONLY \|")
        self.assertRegex(text, r"\| VK Binding \| DEFENSE_IN_DEPTH_ONLY \|")

    def test_report_classifies_oos_dependent(self) -> None:
        (self.scan_root / "Wrapper.sol").write_text(_PROOF_IMPORT_ONLY)
        rc, _, _ = _run(
            "--phase", "all",
            "--root", str(self.scan_root),
            "--template", str(TEMPLATE),
            "--packet-out", str(self.packet),
            "--report-out", str(self.report),
        )
        self.assertEqual(rc, 0, msg=self.report)
        text = self.report.read_text()
        # No in-repo verifier contract; only signal is the gnark import.
        self.assertIn("OOS_DEPENDENT", text)


if __name__ == "__main__":
    unittest.main()
