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
PATTERN = "bridge-proof-domain-bypass-fire22"
DETECTOR = ROOT / "detectors" / "wave17" / "bridge_proof_domain_bypass_fire22.py"
POSITIVE = ROOT / "detectors" / "test_fixtures" / "positive" / "bridge_proof_domain_bypass_fire22.sol"
NEGATIVE = ROOT / "detectors" / "test_fixtures" / "negative" / "bridge_proof_domain_bypass_fire22.sol"


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


class BridgeProofDomainBypassFire22Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        cache_path = ROOT / "detectors" / "test_fixtures" / "cache" / "solidity-files-cache.json"
        cache_bytes = cache_path.read_bytes() if cache_path.exists() else None
        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        try:
            proc = subprocess.run(
                [slither_python, str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )
        finally:
            if cache_bytes is None:
                if cache_path.exists():
                    cache_path.unlink()
            else:
                cache_path.write_bytes(cache_bytes)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_and_fixture_scope_are_source_backed(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("_has_domain_bound_consume_key", detector_text)

        self.assertIn("function settleBridgeReceipt(", positive)
        self.assertIn("sourceChainId", positive)
        self.assertIn("destinationChainId", positive)
        self.assertIn("receiver", positive)
        self.assertIn("MerkleProof.verify(proof, root, leaf)", positive)
        self.assertIn("keccak256(abi.encode(root, sourceReceipt, amount))", positive)
        self.assertNotIn("abi.encode(sourceChainId, destinationChainId, receiver, root", positive)

        self.assertIn("destinationChainId == uint32(block.chainid)", negative)
        self.assertIn("receiver != address(0)", negative)
        self.assertIn(
            "abi.encode(sourceChainId, destinationChainId, receiver, root, sourceReceipt, amount)",
            negative,
        )

    def test_positive_fixture_fires_and_negative_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(NEGATIVE), 0)


if __name__ == "__main__":
    unittest.main()
