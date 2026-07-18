from __future__ import annotations

import json
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "anchor-detector-runner.py"
PATTERN = "raydium-remaining-accounts-bitmap-unverified"
DETECTOR = ROOT / "detectors" / "wave17" / "raydium_remaining_accounts_bitmap_unverified.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "raydium_remaining_accounts_bitmap_unverified"
MIRROR_DIR = ROOT / "detectors" / "fixtures" / PATTERN
POSITIVE_WS = FIXTURE_DIR / "positive"
CLEAN_WS = FIXTURE_DIR / "clean"
MIRROR_POSITIVE_WS = MIRROR_DIR / "positive"
MIRROR_CLEAN_WS = MIRROR_DIR / "clean"
SMOKE = FIXTURE_DIR / "smoke.json"
MIRROR_SMOKE = MIRROR_DIR / "smoke.json"
POSITIVE_LIB = POSITIVE_WS / "programs" / "raydium" / "src" / "lib.rs"
CLEAN_LIB = CLEAN_WS / "programs" / "raydium" / "src" / "lib.rs"
MIRROR_POSITIVE_LIB = MIRROR_POSITIVE_WS / "programs" / "raydium" / "src" / "lib.rs"
MIRROR_CLEAN_LIB = MIRROR_CLEAN_WS / "programs" / "raydium" / "src" / "lib.rs"


def _scan(workspace: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="raydium-anchor-smoke-") as td:
        out = Path(td) / "anchor_findings.json"
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", str(workspace), "--out", str(out)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(f"{proc.stderr}\n{proc.stdout}")
        return json.loads(out.read_text(encoding="utf-8"))


class RaydiumRemainingAccountsBitmapUnverifiedTest(unittest.TestCase):
    def _pattern_findings(self, workspace: Path) -> list[dict]:
        result = _scan(workspace)
        self.assertEqual(result["_meta"]["files_scanned"], 1)
        return [f for f in result["findings"] if f["pattern"] == PATTERN]

    def test_detector_reference_and_fixture_metadata(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE_LIB.read_text(encoding="utf-8")
        clean_text = CLEAN_LIB.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        mirror_payload = json.loads(MIRROR_SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("PROMOTION_ALLOWED = False", detector_text)
        self.assertIn("remaining_accounts", detector_text)
        self.assertIn("require_keys_eq", detector_text)

        self.assertIn("backend: anchor", reference_text)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", reference_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn("fixture_mirrors:", reference_text)
        self.assertIn(str(POSITIVE_LIB.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN_LIB.relative_to(ROOT)), reference_text)
        self.assertIn(str(MIRROR_POSITIVE_LIB.relative_to(ROOT)), reference_text)
        self.assertIn(str(MIRROR_CLEAN_LIB.relative_to(ROOT)), reference_text)
        self.assertIn("remaining_accounts[i]", reference_text)

        self.assertIn("pub fn increase_liquidity", positive_text)
        self.assertIn("ctx.remaining_accounts.get(0).unwrap()", positive_text)
        self.assertIn("bitmap_extension.pool_id", positive_text)
        self.assertNotIn("require_keys_eq!", positive_text)

        self.assertIn("pub fn increase_liquidity", clean_text)
        self.assertIn("ctx.remaining_accounts.get(0).unwrap()", clean_text)
        self.assertIn("bitmap_extension.pool_id", clean_text)
        self.assertIn("require_keys_eq!(bitmap_extension.pool_id, ctx.accounts.pool_state.key())", clean_text)

        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("anchor-detector-runner.py", payload["positive_command"])
        self.assertIn("remaining_accounts", payload["limitation_note"])

        self.assertEqual(mirror_payload["pattern"], PATTERN)
        self.assertEqual(mirror_payload["fixture_id"], PATTERN)
        self.assertEqual(mirror_payload["positive_hits"], 1)
        self.assertEqual(mirror_payload["clean_hits"], 0)
        self.assertEqual(mirror_payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("Compatibility mirror", mirror_payload["limitation_note"])

    def test_hyphenated_fixture_mirror_stays_in_sync(self) -> None:
        self.assertEqual(POSITIVE_LIB.read_text(encoding="utf-8"), MIRROR_POSITIVE_LIB.read_text(encoding="utf-8"))
        self.assertEqual(CLEAN_LIB.read_text(encoding="utf-8"), MIRROR_CLEAN_LIB.read_text(encoding="utf-8"))

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        positive_findings = self._pattern_findings(POSITIVE_WS)
        clean_findings = self._pattern_findings(CLEAN_WS)

        self.assertEqual(len(positive_findings), 1, positive_findings)
        self.assertEqual(positive_findings[0]["evidence_class"], "scaffolded_unverified")
        self.assertEqual(positive_findings[0]["region_kind"], "handler")
        self.assertEqual(positive_findings[0]["region_name"], "increase_liquidity")
        self.assertEqual(len(clean_findings), 0, clean_findings)


if __name__ == "__main__":
    unittest.main()
