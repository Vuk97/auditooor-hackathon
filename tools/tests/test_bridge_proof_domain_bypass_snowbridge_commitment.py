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
PATTERN = "bridge-proof-domain-bypass-snowbridge-commitment"
DETECTOR = ROOT / "detectors" / "wave17" / "bridge_proof_domain_bypass_snowbridge_commitment.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "bridge_proof_domain_bypass_snowbridge_commitment"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
SNOWBRIDGE_VERIFICATION = (
    ROOT
    / "reports"
    / "external_recall_snapshots"
    / "snowbridge_4855ace3_parent"
    / "contracts"
    / "src"
    / "Verification.sol"
)
SNOWBRIDGE_BEEFY = (
    ROOT
    / "reports"
    / "external_recall_snapshots"
    / "snowbridge_4855ace3_parent"
    / "contracts"
    / "src"
    / "BeefyClient.sol"
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


class BridgeProofDomainBypassSnowbridgeCommitmentTest(unittest.TestCase):
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
        self.assertIn(PATTERN, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_compiles_and_metadata_is_not_submit_ready(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("SUBMISSION_POSTURE = \"NOT_SUBMIT_READY\"", detector_text)
        self.assertIn("_has_snowbridge_commitment_bypass_shape", detector_text)

        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["verification_tier"], "tier-2-verified-public-archive")

    def test_fixture_pair_models_missing_and_present_commitment_binding(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("function verifyCommitment(", positive)
        self.assertIn("bytes32 commitment", positive)
        self.assertIn("verifyMMRLeafProof", positive)
        self.assertIn("proof.unboundParachainHeadHash", positive)
        self.assertNotIn("isCommitmentInHeaderDigest(commitment", positive)
        self.assertNotIn("createParachainHeaderMerkleLeaf(encodedParaID", positive)

        self.assertIn("function verifyCommitment(", clean)
        self.assertIn("isCommitmentInHeaderDigest(commitment, proof.header, isV2)", clean)
        self.assertIn("createParachainHeaderMerkleLeaf(encodedParaID, proof.header)", clean)
        self.assertIn("commitment == bytes32(header.digestItems[i].data[1:])", clean)

    def test_snowbridge_source_evidence_contains_clean_binding_chain(self) -> None:
        verification = SNOWBRIDGE_VERIFICATION.read_text(encoding="utf-8")
        beefy = SNOWBRIDGE_BEEFY.read_text(encoding="utf-8")

        self.assertIn("isCommitmentInHeaderDigest(commitment, proof.header, isV2)", verification)
        self.assertIn("createParachainHeaderMerkleLeaf(encodedParaID, proof.header)", verification)
        self.assertIn("createMMRLeaf(proof.leafPartial, parachainHeadsRoot)", verification)
        self.assertIn("verifyMMRLeafProof", verification)
        self.assertIn("ensureProvidesMMRRoot(commitment)", beefy)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
