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
PATTERN = "w68-approval-replay-missing-nonce"
DETECTOR = ROOT / "detectors" / "wave68" / "w68_approval_replay_missing_nonce.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "w68_approval_replay_missing_nonce"
MIRROR_DIR = ROOT / "detectors" / "fixtures" / PATTERN
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
MIRROR_POSITIVE = MIRROR_DIR / "positive.sol"
MIRROR_CLEAN = MIRROR_DIR / "clean.sol"
MIRROR_SMOKE = MIRROR_DIR / "smoke.json"
TIER_REGISTRY = ROOT / "detectors" / "_tier_registry.yaml"
OBSIDIAN_PATTERN = ROOT / "obsidian-vault" / "patterns" / f"{PATTERN}.md"


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


class ApprovalReplayRecallLiftTest(unittest.TestCase):
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
        self.assertNotIn("UNKNOWN predicate key", proc.stdout)
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_pattern_compile_round_trip_matches_generated_detector(self) -> None:
        compiler = _load_pattern_compile()
        with tempfile.TemporaryDirectory(prefix=".pattern_compile_approval_replay_", dir=ROOT) as tmp:
            out_dir = Path(tmp) / "wave68"
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

    def test_detector_reference_and_fixture_metadata(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        mirror_positive_text = MIRROR_POSITIVE.read_text(encoding="utf-8")
        mirror_clean_text = MIRROR_CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        mirror_payload = json.loads(MIRROR_SMOKE.read_text(encoding="utf-8"))
        tier_registry_text = TIER_REGISTRY.read_text(encoding="utf-8")
        obsidian_pattern_text = OBSIDIAN_PATTERN.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("writes_state_var_matching_regex", detector_text)
        self.assertIn("nonce|deadline|expiry|expires|timestamp", detector_text)
        self.assertIn("Signed approval replayed after intended use", detector_text)
        self.assertIn("contract.source_matches_regex", reference_text)
        self.assertIn("contract.has_function_matching", reference_text)
        self.assertIn("approval-replay", reference_text)
        self.assertIn("fixture_mirrors:", reference_text)
        self.assertIn(str(MIRROR_POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(MIRROR_CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn("delegateApproval", positive_text)
        self.assertIn("delegateApproval", clean_text)
        self.assertEqual(positive_text, mirror_positive_text)
        self.assertEqual(clean_text, mirror_clean_text)
        self.assertIn("domainSeparator", clean_text)
        self.assertNotIn("domainSeparator", positive_text)
        self.assertNotIn("nonce", positive_text)
        self.assertIn("permission", reference_text)
        self.assertIn("fixture_pair: detectors/fixtures/w68_approval_replay_missing_nonce", tier_registry_text)
        self.assertIn("smoke_test_command: python3 detectors/run_custom.py --tier=ALL detectors/fixtures/w68_approval_replay_missing_nonce/positive.sol", tier_registry_text)
        self.assertIn("Signed approval replayed after intended use", obsidian_pattern_text)
        self.assertIn("detectors/fixtures/w68_approval_replay_missing_nonce", obsidian_pattern_text)
        self.assertIn("Fixture mirror", (ROOT / "obsidian-vault" / "detectors" / "wave68" / f"{PATTERN}.md").read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("nonce, deadline, domain, salt", payload["limitation_note"])
        self.assertEqual(mirror_payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(mirror_payload["pattern"], PATTERN)
        self.assertEqual(mirror_payload["positive_fixture_path"], "detectors/fixtures/w68-approval-replay-missing-nonce/positive.sol")
        self.assertEqual(mirror_payload["clean_fixture_path"], "detectors/fixtures/w68-approval-replay-missing-nonce/clean.sol")

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)
        self.assertEqual(self._hits(MIRROR_POSITIVE), 1)
        self.assertEqual(self._hits(MIRROR_CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
