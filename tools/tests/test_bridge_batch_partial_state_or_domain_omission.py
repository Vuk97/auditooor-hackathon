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
PATTERN = "bridge-batch-partial-state-or-domain-omission"
DETECTOR = ROOT / "detectors" / "wave17" / "bridge_batch_partial_state_or_domain_omission.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "bridge_batch_partial_state_or_domain_omission"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
SNOWBRIDGE_GATEWAY = (
    ROOT
    / "reports"
    / "external_recall_snapshots"
    / "snowbridge_4855ace3_parent"
    / "contracts"
    / "src"
    / "Gateway.sol"
)
OLD_BATCH_PATTERN = "bridge-batch-dispatch-try-catch-continue-partial-state"


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


class BridgeBatchPartialStateOrDomainOmissionTest(unittest.TestCase):
    def _hits(self, fixture: Path, pattern: str = PATTERN) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), pattern],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(pattern, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_reference_and_fixture_metadata(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        smoke = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("slither_source_shape", reference_text)
        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)
        self.assertEqual(smoke["pattern"], PATTERN)
        self.assertEqual(smoke["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(smoke["verification_tier"], "tier-2-verified-public-archive")

    def test_fixture_pair_models_unsafe_and_safe_batch_finalization(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("inboundNonce[message.nonce] = true;", positive)
        self.assertIn("bool success = dispatchBatch(message);", positive)
        self.assertIn("catch {\n                    return false;", positive)
        self.assertNotIn("if (!success)", positive)

        self.assertIn("if (!success) {\n            revert CommandFailed();", clean)
        self.assertIn("inboundNonce[message.nonce] = true;\n        emit", clean)
        self.assertIn("inboundNonce[message.nonce] = false;", clean)

    def test_snowbridge_source_evidence_has_the_target_shape(self) -> None:
        gateway = SNOWBRIDGE_GATEWAY.read_text(encoding="utf-8")

        submit_marker = gateway.index("$.inboundNonce.set(message.nonce);")
        dispatch_call = gateway.index("bool success = v2_dispatch(message);")
        event_emit = gateway.index("emit IGatewayV2.InboundMessageDispatched")
        dispatcher = gateway.index("function v2_dispatch(InboundMessageV2 calldata message)")

        self.assertLess(submit_marker, dispatch_call)
        self.assertLess(dispatch_call, event_emit)
        self.assertIn("for (uint256 i = 0; i < message.commands.length; i++)", gateway[dispatcher:])
        self.assertIn("catch {\n                    return false;", gateway[dispatcher:])
        self.assertNotIn("if (!success)", gateway[dispatch_call:event_emit])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)

    def test_old_exact_continue_detector_does_not_cover_return_false_variant(self) -> None:
        self.assertEqual(self._hits(POSITIVE, OLD_BATCH_PATTERN), 0)


if __name__ == "__main__":
    unittest.main()
