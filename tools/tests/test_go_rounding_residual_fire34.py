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
DETECTOR = ROOT / "detectors" / "go_wave1" / "go-rounding-residual-fire34.py"
FIXTURE_DIR = ROOT / "detectors" / "go_wave1" / "test_fixtures"
PATTERN = "go-rounding-residual-fire34"
POSITIVE = FIXTURE_DIR / "go_rounding_residual_fire34_positive.go"
NEGATIVE = FIXTURE_DIR / "go_rounding_residual_fire34_negative.go"


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


class GoRoundingResidualFire34Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python_ast = _python_with_go_parser()
        if python_ast is None:
            self.skipTest("no Python interpreter can load the Go tree-sitter parser")

        with tempfile.NamedTemporaryFile(prefix=".go_rounding_residual_fire34_", suffix=".log") as tmp:
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
        text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn('DETECTOR_ID = "go_wave1.go-rounding-residual-fire34"', text)
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", text)
        self.assertIn("attack_class: rounding-direction-attack", text)
        self.assertIn("post_priorities_go.md", text)
        self.assertIn("go-rounding-direction-fee-fire32.py", text)
        self.assertIn("go-rounding-fee-direction-fire33.py", text)
        self.assertIn("r94-loop-royalty-distribution-rounding-dust-siphon.yaml", text)
        self.assertIn("NOT_SUBMIT_READY", text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        positive_hits, positive_log = self._hits(POSITIVE)
        negative_hits, negative_log = self._hits(NEGATIVE)
        self.assertEqual(positive_hits, 4, positive_log)
        self.assertEqual(negative_hits, 0, negative_log)
        self.assertIn("DistributeFeeRemainderToFirstParticipant", positive_log)
        self.assertIn("CreditSdkIntResidualToAttacker", positive_log)
        self.assertIn("SendLegacyDecimalDustToModule", positive_log)
        self.assertIn("AssignRewardLeftoverToFirstReceiver", positive_log)
        self.assertIn("rounding-direction-attack", positive_log)
        self.assertIn("NOT_SUBMIT_READY", positive_log)

    def test_false_positive_boundaries_are_locked(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")
        detector = DETECTOR.read_text(encoding="utf-8")
        for path in (DETECTOR, POSITIVE, NEGATIVE, Path(__file__)):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2014", text)
            self.assertNotIn("\u2013", text)

        self.assertIn("remainder := totalFee % uint64(len(participants))", positive)
        self.assertIn("residual := totalFee.Sub(share.MulRaw(int64(len(accounts))))", positive)
        self.assertIn("dust := feeDec.Sub(NewLegacyDecFromInt(whole)).TruncateInt()", positive)
        self.assertIn("leftover := totalRewards - rewardShare*uint64(len(receivers))", positive)

        self.assertIn("if remainder != 0", negative)
        self.assertIn("k.RemainderCarry += remainder", negative)
        self.assertIn("participants[len(participants)-1]", negative)
        self.assertIn("if dust.GT(MaxDust)", negative)
        self.assertIn("DebugRemainder", negative)
        self.assertIn("explicit accumulator", detector)


if __name__ == "__main__":
    unittest.main()
