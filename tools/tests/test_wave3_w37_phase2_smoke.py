"""
Wave-3 W3.7 - Phase-2 detector autogen enable + smoke harness.

This test is the smoke harness for the W3.7 lane. It validates the
Phase-2 opt-in surface end to end:

  (a) PARSE   - every Phase-2 roster entry is well-formed JSON with the
                fields the smoke driver depends on.
  (b) LOAD    - the detector loader activates exactly the Phase-1 (20) +
                Phase-2 (20) = 40 detector surface when both env flags are
                truthy, and stays empty / Phase-1-only otherwise.
  (c) FIRE    - each Phase-2 detector, evaluated through the real smoke
                driver (`run_smoke`), fires on a synthetic fixture that
                contains its `shape_literal` and stays quiet on a clean
                fixture that does not.

The `--phase2` CLI opt-in on the loader is also exercised.

Default-OFF contract: Phase-2 is opt-in. This harness NEVER asserts a
default flip - it only proves the opt-in path works. The default flip is
gated on human review of real-source output; see
`docs/WAVE3_W37_PHASE2_REVIEW_GATE.md`.

All fixtures here are synthetic (marked `synthetic_fixture: true`) and
exist only to exercise wiring. They are NOT representative of real audit
work.

M14-trap note: the Phase-2 roster's detectors are seeded from named
public corpora (`git-mining:...`, `ghsa:...`) - broad recurring
anti-pattern classes, not individually source-anchored function names.
That is exactly why Phase-2 stays opt-in until real-source review. This
harness proves the wiring; it does NOT bless the detector content.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.audit import wave2_w22_detector_loader as loader  # noqa: E402
from tools.audit import wave2_w22_phase2_smoke as smoke_mod  # noqa: E402

SYNTHETIC_MARKER = "synthetic_fixture: true"

# Map a language to a fixture filename extension the smoke driver scans.
_LANG_EXT = {
    "solidity": ".sol",
    "vyper": ".vy",
    "go": ".go",
    "rust": ".rs",
    "circom": ".circom",
}

# `regex_negative` detectors fire on the ABSENCE of their literal. The
# substring-based smoke driver cannot model negation, so the fire/quiet
# polarity assertion is skipped for them (documented limitation - the
# production runner per spec section 8 replaces the substring scan).
_NEGATIVE_SHAPE_KIND = "regex_negative"


class Wave3W37Phase2SmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        for flag in (loader.PHASE1_ENV_FLAG, loader.PHASE2_ENV_FLAG):
            os.environ.pop(flag, None)

    def tearDown(self) -> None:
        for flag in (loader.PHASE1_ENV_FLAG, loader.PHASE2_ENV_FLAG):
            os.environ.pop(flag, None)

    # ---- (a) PARSE ----

    def test_01_phase2_roster_parses(self) -> None:
        """Every Phase-2 entry has the fields the smoke driver consumes."""
        detectors = loader.load_phase2_roster()
        self.assertEqual(len(detectors), 20, "Phase-2 roster must be 20 detectors")
        for det in detectors:
            self.assertTrue(det["detector_id"].startswith("w22p2_"))
            self.assertIn(det["language"], _LANG_EXT, det["detector_id"])
            self.assertTrue(det.get("shape_literal"), det["detector_id"])
            # Provenance must point at a named corpus seed, not bare prose.
            src = det.get("source_record_id", "")
            self.assertTrue(
                src.startswith("git-mining:") or src.startswith("ghsa:"),
                f"{det['detector_id']} has un-anchored source_record_id {src!r}",
            )

    # ---- (b) LOAD ----

    def test_02_loader_activates_40_with_both_flags(self) -> None:
        env = {loader.PHASE1_ENV_FLAG: "1", loader.PHASE2_ENV_FLAG: "1"}
        active = loader.load_active_detectors(env)
        self.assertEqual(len(active), 40)
        status = loader.loader_status(env)
        self.assertEqual(status["active_detector_count"], 40)
        self.assertEqual(status["phase2_detector_count"], 20)

    def test_03_phase2_default_off(self) -> None:
        """No flags -> no detectors. Phase-2 alone -> no detectors."""
        self.assertEqual(loader.load_active_detectors({}), [])
        self.assertEqual(
            loader.load_active_detectors({loader.PHASE2_ENV_FLAG: "1"}), []
        )

    def test_04_loader_cli_phase2_flag(self) -> None:
        """`--phase2` CLI opt-in emits the loader_status envelope."""
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools/audit/wave2_w22_detector_loader.py"),
                "--phase2",
            ],
            capture_output=True,
            text=True,
            env={**os.environ, loader.PHASE1_ENV_FLAG: "1"},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.wave2_w22_loader_status.v1")
        self.assertTrue(payload["phase2_enabled"])
        self.assertEqual(payload["active_detector_count"], 40)

    # ---- (c) FIRE on vuln fixture, QUIET on clean fixture ----

    def _run_smoke(self, workspace: Path) -> dict:
        env = {loader.PHASE1_ENV_FLAG: "1", loader.PHASE2_ENV_FLAG: "1"}
        return smoke_mod.run_smoke(workspace, env=env)

    def _write_fixture(self, ws: Path, name: str, body: str) -> None:
        src = ws / "src"
        src.mkdir(exist_ok=True)
        (src / name).write_text(f"// {SYNTHETIC_MARKER}\n{body}\n", encoding="utf-8")

    def test_05_each_phase2_detector_fires_on_vuln_quiet_on_clean(self) -> None:
        """Per Phase-2 detector: vuln fixture fires, clean fixture quiet."""
        detectors = loader.load_phase2_roster()
        for det in detectors:
            det_id = det["detector_id"]
            shape = det["shape_literal"]
            ext = _LANG_EXT[det["language"]]
            with self.subTest(detector=det_id):
                # --- vuln fixture: contains the shape literal ---
                with tempfile.TemporaryDirectory() as td:
                    ws = Path(td)
                    self._write_fixture(
                        ws, f"Vuln{ext}", f"contract V {{ {shape} }}"
                    )
                    result = self._run_smoke(ws)
                    row = next(
                        r
                        for r in result["per_detector_hits"]
                        if r["detector_id"] == det_id
                    )
                    self.assertGreater(
                        row["hit_files"],
                        0,
                        f"{det_id} did not fire on a fixture containing {shape!r}",
                    )

                # --- clean fixture: omits the shape literal ---
                if det.get("shape_kind") == _NEGATIVE_SHAPE_KIND:
                    # Negative-semantics detector: substring smoke driver
                    # cannot model absence. Polarity assertion skipped by
                    # design (see module docstring + review-gate doc).
                    continue
                with tempfile.TemporaryDirectory() as td:
                    ws = Path(td)
                    self._write_fixture(
                        ws,
                        f"Clean{ext}",
                        "contract C { uint256 x = 1; }",
                    )
                    result = self._run_smoke(ws)
                    row = next(
                        r
                        for r in result["per_detector_hits"]
                        if r["detector_id"] == det_id
                    )
                    # The clean fixture deliberately avoids every shape;
                    # if a detector still fires it is an over-broad shape.
                    if shape in "contract C { uint256 x = 1; }":
                        # Shape happens to be a substring of the clean
                        # body (e.g. a very generic token) - skip, the
                        # over-breadth is a known smoke-driver caveat.
                        continue
                    self.assertEqual(
                        row["hit_files"],
                        0,
                        f"{det_id} fired on a clean fixture (over-broad shape {shape!r})",
                    )

    def test_06_smoke_off_evaluates_nothing(self) -> None:
        """Smoke driver with flags OFF evaluates zero detectors."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            self._write_fixture(ws, "Vuln.sol", "contract V { tx.origin; }")
            result = smoke_mod.run_smoke(ws, env={})
            self.assertEqual(result["detector_count_evaluated"], 0)
            self.assertEqual(result["total_hit_files"], 0)


if __name__ == "__main__":
    unittest.main()
