from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
TOOL = ROOT / "tools" / "pattern-compile.py"
PATTERN = "override-applied-but-accounting-uses-original-state"
DETECTOR = ROOT / "detectors" / "wave17" / "override_applied_but_accounting_uses_original_state.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "override_applied_but_accounting_uses_original_state"
MIRROR_DIR = ROOT / "detectors" / "fixtures" / PATTERN
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
MANIFEST = FIXTURE_DIR / "manifest.json"
SMOKE = FIXTURE_DIR / "smoke.json"
MIRROR_POSITIVE = MIRROR_DIR / "positive.sol"
MIRROR_CLEAN = MIRROR_DIR / "clean.sol"
MIRROR_MANIFEST = MIRROR_DIR / "manifest.json"
MIRROR_SMOKE = MIRROR_DIR / "smoke.json"


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


class OverrideAppliedButAccountingUsesOriginalStateTest(unittest.TestCase):
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
            prefix=".pattern_compile_override_original_state_",
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

    def test_detector_reference_and_fixture_metadata_stay_scoped(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        smoke = json.loads(SMOKE.read_text(encoding="utf-8"))
        mirror_manifest = json.loads(MIRROR_MANIFEST.read_text(encoding="utf-8"))
        mirror_smoke = json.loads(MIRROR_SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("function.body_ordered_regex", detector_text)
        self.assertIn("original|snapshot|cached|base|prior|old", detector_text)
        self.assertIn("latest|current|active|fresh", detector_text)

        self.assertIn("status: not-submit-ready", reference_text)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", reference_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn("fixture_mirrors:", reference_text)
        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn("original snapshot instead of the refreshed active state", reference_text)

        self.assertIn("CampaignState memory originalCampaign = campaigns[campaignId];", positive_text)
        self.assertIn("campaigns[campaignId].rate = newRate;", positive_text)
        self.assertIn("remaining =", positive_text)
        self.assertIn("originalCampaign.budget", positive_text)
        self.assertIn("originalCampaign.rate", positive_text)

        self.assertIn("CampaignState memory activeCampaign = campaigns[campaignId];", clean_text)
        self.assertIn("activeCampaign.budget", clean_text)
        self.assertIn("activeCampaign.rate", clean_text)

        self.assertEqual(manifest["pattern"], PATTERN)
        self.assertEqual(manifest["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(manifest["promotion_allowed"])
        self.assertEqual(manifest["submission_posture"], "NOT_SUBMIT_READY")

        self.assertEqual(smoke["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(smoke["pattern"], PATTERN)
        self.assertEqual(smoke["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(smoke["positive_hits"], 1)
        self.assertEqual(smoke["vulnerable_hits"], 1)
        self.assertEqual(smoke["clean_hits"], 0)
        self.assertEqual(smoke["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(smoke["promotion_allowed"])
        self.assertEqual(smoke["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("original snapshot", smoke["limitation_note"])

        self.assertEqual(mirror_manifest["pattern"], PATTERN)
        self.assertEqual(mirror_manifest["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(mirror_smoke["pattern"], PATTERN)
        self.assertEqual(mirror_smoke["positive_hits"], 1)
        self.assertEqual(mirror_smoke["clean_hits"], 0)
        self.assertEqual(mirror_smoke["submission_posture"], "NOT_SUBMIT_READY")

    def test_hyphenated_fixture_mirror_stays_in_sync(self) -> None:
        self.assertEqual(POSITIVE.read_text(encoding="utf-8"), MIRROR_POSITIVE.read_text(encoding="utf-8"))
        self.assertEqual(CLEAN.read_text(encoding="utf-8"), MIRROR_CLEAN.read_text(encoding="utf-8"))

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
