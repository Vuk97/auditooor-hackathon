from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "lang-detect.py"
DETECTOR = ROOT / "detectors" / "go_wave1" / "go-signature-domain-replay-fire37.py"
FIXTURE_DIR = ROOT / "detectors" / "go_wave1" / "test_fixtures"
PATTERN = "go-signature-domain-replay-fire37"
POSITIVE = FIXTURE_DIR / "go_signature_domain_replay_fire37_positive.go"
NEGATIVE = FIXTURE_DIR / "go_signature_domain_replay_fire37_negative.go"
RESULT = ROOT / "reports" / "detector_lift_fire37_20260605" / "worker_results" / "worker_ii_results.md"


def _python_with_go_parser() -> str | None:
    candidates = [
        os.environ.get("AUDITOOOR_PYTHON_AST"),
        sys.executable,
        "python3",
        "python3.14",
        "python3.13",
        "python3.12",
        "python3.11",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [
                    candidate,
                    "-c",
                    "from tree_sitter_language_pack import get_parser; get_parser('go')",
                ],
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


class GoSignatureDomainReplayFire37Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python_ast = _python_with_go_parser()
        if python_ast is None:
            self.skipTest("no Python interpreter can load the Go tree-sitter parser")

        with tempfile.NamedTemporaryFile(prefix=".go_signature_domain_replay_fire37_", suffix=".log") as tmp:
            proc = subprocess.run(
                [
                    python_ast,
                    str(TOOL),
                    "--lang",
                    "go",
                    str(FIXTURE_DIR),
                    "--only",
                    PATTERN,
                    "--file",
                    str(fixture),
                    "--log",
                    tmp.name,
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            match = re.search(r"total hits:\s*(\d+)", proc.stdout)
            self.assertIsNotNone(match, proc.stdout)
            log_text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")
            return int(match.group(1)), proc.stdout + "\n" + log_text

    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        detector = DETECTOR.read_text(encoding="utf-8")
        self.assertIn('DETECTOR_ID = "go_wave1.go-signature-domain-replay-fire37"', detector)
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector)
        self.assertIn("attack_class: signature-replay-cross-domain", detector)
        self.assertIn("reports/detector_lift_fire36_20260605/post_priorities_go.md", detector)
        self.assertIn("reference/patterns.dsl/signature-replay-cross-domain.yaml", detector)
        self.assertIn("detectors/rust_wave1/signature_domain_replay_fire36.py", detector)
        self.assertIn("go.spark.coop_exit.key_tweak_resumability.yaml", detector)
        self.assertIn("NOT_SUBMIT_READY", detector)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        positive_hits, positive_log = self._hits(POSITIVE)
        negative_hits, negative_log = self._hits(NEGATIVE)
        self.assertEqual(positive_hits, 4, positive_log)
        self.assertEqual(negative_hits, 0, negative_log)
        self.assertIn("ExecuteEd25519Intent", positive_log)
        self.assertIn("ClaimSecp256K1Authorization", positive_log)
        self.assertIn("SettleBLSAggregateAuthorization", positive_log)
        self.assertIn("FinalizeFrostShareAuthorization", positive_log)
        self.assertIn("signature-replay-cross-domain", positive_log)
        self.assertIn("NOT_SUBMIT_READY", positive_log)

    def test_scope_boundaries_are_locked(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")
        result = RESULT.read_text(encoding="utf-8")
        detector = DETECTOR.read_text(encoding="utf-8")

        for path in (DETECTOR, POSITIVE, NEGATIVE, RESULT, Path(__file__)):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2014", text)
            self.assertNotIn("\u2013", text)

        self.assertIn("ed25519.Verify(pub, digest[:], sig)", positive)
        self.assertIn("secp256k1.VerifySignature(pubkey, digest[:], sig)", positive)
        self.assertIn("FastAggregateVerify(publicKeys, challenge, aggregateSignature)", positive)
        self.assertIn("frost.VerifySignatureShare(publicKey, challenge, share)", positive)
        self.assertIn("transcript.AppendBytes(\"payload\", req.PayloadHash[:])", positive)

        self.assertIn("signedBytes = append(signedBytes, []byte(chainID)...)", negative)
        self.assertIn("signedBytes = append(signedBytes, domainSeparator[:]...)", negative)
        self.assertIn("signedBytes = append(signedBytes, sessionID[:]...)", negative)
        self.assertIn("signedBytes = append(signedBytes, []byte(signerRole)...)", negative)
        self.assertIn("transcript.AppendBytes(\"participant_set\", participantSetHash[:])", negative)
        self.assertIn("transcript.AppendBytes(\"purpose\", []byte(purpose))", negative)

        self.assertIn("False-positive boundaries", result)
        self.assertIn("source-review candidates only", detector)


if __name__ == "__main__":
    unittest.main()
