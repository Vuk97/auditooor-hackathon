from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
TOOL = ROOT / "tools" / "pattern-compile.py"
PATTERN = "delegation-token-still-listed-old-delegate"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wave17" / "delegation_token_still_listed_old_delegate.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "delegation_token_still_listed_old_delegate"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
GOLOM_ORIGIN_POSITIVE = (
    ROOT / "detectors" / "fixtures" / "delegation_reassignment_stale_vote_source" / "origin_positive.sol"
)
STALE_VOTE_SOURCE_POSITIVE = (
    ROOT / "detectors" / "fixtures" / "delegation_reassignment_stale_vote_source" / "positive.sol"
)
STALE_VOTE_SOURCE_CLEAN = (
    ROOT / "detectors" / "fixtures" / "delegation_reassignment_stale_vote_source" / "clean.sol"
)
W68_SCALAR_POSITIVE = (
    ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "delegation_power_inflation_positive.sol"
)
OLD_SOURCE_DEBIT_POSITIVE = (
    ROOT / "detectors" / "fixtures" / "delegation_power_credit_without_old_source_debit" / "positive.sol"
)
SOURCE_BURN_POSITIVE = (
    ROOT / "detectors" / "fixtures" / "delegation_power_redelegate_without_source_burn" / "positive.sol"
)


def _load_pattern_compile():
    spec = importlib.util.spec_from_file_location("pattern_compile", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


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


class DelegationTokenStillListedOldDelegateTest(unittest.TestCase):
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
        self.assertNotIn("No custom detectors found", proc.stdout)
        self.assertNotIn("UNKNOWN predicate key", proc.stdout)
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_pattern_compile_round_trip_matches_generated_detector(self) -> None:
        compiler = _load_pattern_compile()
        with tempfile.TemporaryDirectory(
            prefix=".pattern_compile_delegation_token_still_listed_old_delegate_",
            dir=ROOT,
        ) as tmp:
            out_dir = Path(tmp) / "wave17"
            compiled = compiler.compile_pattern(
                REFERENCE,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            self.assertTrue(compiled)
            generated = out_dir / DETECTOR.name
            self.assertTrue(generated.is_file(), f"missing generated detector: {generated}")
            self.assertEqual(
                DETECTOR.read_text(encoding="utf-8"),
                generated.read_text(encoding="utf-8"),
            )

    def test_reference_yaml_and_smoke_metadata_stay_aligned(self) -> None:
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn("delegation-power-inflation", reference_text)
        self.assertIn(
            "vuln: detectors/fixtures/delegation_token_still_listed_old_delegate/positive.sol",
            reference_text,
        )
        self.assertIn(
            "clean: detectors/fixtures/delegation_token_still_listed_old_delegate/clean.sol",
            reference_text,
        )

        self.assertIn("tokensByDelegate[newDelegate].push(tokenId);", positive_text)
        self.assertNotIn("_removeTokenFromDelegate(oldDelegate, tokenId);", positive_text)
        self.assertIn("_removeTokenFromDelegate(oldDelegate, tokenId);", clean_text)

        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["golom_origin_positive_hits"], 1)
        self.assertEqual(payload["stale_vote_source_positive_hits"], 1)
        self.assertEqual(payload["stale_vote_source_clean_hits"], 0)
        self.assertEqual(payload["w68_scalar_positive_hits"], 0)
        self.assertEqual(payload["old_source_debit_positive_hits"], 0)
        self.assertEqual(payload["source_burn_positive_hits"], 0)
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["promotion_allowed"])

    def test_positive_fires_clean_is_quiet_and_sibling_split_holds(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)
        self.assertEqual(self._hits(GOLOM_ORIGIN_POSITIVE), 1)
        self.assertEqual(self._hits(STALE_VOTE_SOURCE_POSITIVE), 1)
        self.assertEqual(self._hits(STALE_VOTE_SOURCE_CLEAN), 0)
        self.assertEqual(self._hits(W68_SCALAR_POSITIVE), 0)
        self.assertEqual(self._hits(OLD_SOURCE_DEBIT_POSITIVE), 0)
        self.assertEqual(self._hits(SOURCE_BURN_POSITIVE), 0)


if __name__ == "__main__":
    unittest.main()
