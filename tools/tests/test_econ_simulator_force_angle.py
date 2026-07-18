#!/usr/bin/env python3
"""iter13 T3 — `--force-angle` CLI override for `tools/econ-simulator.py`.

Context (iter12 T2 finding): R77-06 draft predates the `A-<ANGLE>` token
convention, so the packager's `detect_attack_angles()` returns `[]` and
no harness is emitted. `--force-angle` is the operator-facing override
on the CONSUMER side (econ-simulator) — it lets the operator pass an
explicit angle to bootstrap a harness directly when the bundle lacks
one. No edits to `tools/submission-packager.py`; no edits to
`tools/angle_map.json`.

Three offline tests (stdlib-only, no subprocess reaches network / real
halmos / real anvil):

  1. `test_force_angle_emits_harness_for_mapped_angle` — passing
     `--force-angle A-DONATION-CAPTURE` on a bundle LACKING a harness
     copies the family harness to `<bundle>/harnesses/<angle>.t.sol`.
     Advisory-only flags preserved on the manifest.

  2. `test_force_angle_rejects_unmapped` — `--force-angle A-FOOBAR`
     (unmapped in `tools/angle_map.json`) returns exit 2, manifest
     `status: error`, reason cites the unmapped angle verbatim.

  3. `test_force_angle_records_provenance_in_manifest` — the manifest
     includes `angle_source: "force-angle-cli"` as a provenance field
     (NOT a status string — locked vocab unchanged).

Locked-vocab regression guard embedded in #3: the manifest's `status`
remains inside `ALLOWED_STATUSES`.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "econ-simulator.py"
ANGLE_MAP = ROOT / "tools" / "angle_map.json"


def _make_bundle(tmp: Path) -> Path:
    """Minimal packaged-bundle skeleton — NO pre-existing harness.

    iter13 T3's fix path explicitly covers bundles where the packager
    produced no harness (legacy-draft gap). We therefore omit any
    `<bundle>/harnesses/` or `<bundle>/econ-simulator/harness.t.sol`
    file — `--force-angle` has to bootstrap it from scratch.
    """
    bundle = tmp / "packaged" / "r77-06-legacy"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "source-draft.md").write_text(
        "# Adapter Donation Capture\n"
        "**Severity**: Medium\n\n"
        "Legacy draft body — no `A-<ANGLE>` token here. iter12 T2 "
        "surfaced this as the blocker for live-mode harness emission.\n"
    )
    (bundle / "evidence-matrix.json").write_text(json.dumps({
        "schema_version": 1,
        "severity": "MEDIUM",
        "rows": [],
        "summary": {"ready_verdict": "UNKNOWN"},
    }, indent=2))
    (bundle / "manifest.json").write_text(json.dumps({
        "workspace": "polymarket",
    }, indent=2))
    return bundle


def _run_sim(args, *, env=None):
    """Dry-run by default — `--force-angle` bootstrap runs BEFORE live-mode,
    so even in dry-run the harness copy is exercised.
    """
    run_env = os.environ.copy()
    run_env.setdefault("ECON_SIM_DRY_RUN", "1")
    if env:
        run_env.update(env)
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=ROOT, env=run_env, capture_output=True, text=True,
    )


class EconSimulatorForceAngleTest(unittest.TestCase):

    # ------------------------------------------------------------------
    # 1. Mapped angle → harness copied; advisory-only flags preserved.
    # ------------------------------------------------------------------
    def test_force_angle_emits_harness_for_mapped_angle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _make_bundle(Path(tmp))
            out_path = bundle / "econ-simulator" / "A-DONATION-CAPTURE.json"

            # Precondition: no harness on disk yet.
            harness_dest = bundle / "harnesses" / "A-DONATION-CAPTURE.t.sol"
            self.assertFalse(harness_dest.is_file())

            result = _run_sim([
                "--bundle", str(bundle),
                "--angle", "A-DONATION-CAPTURE",
                "--force-angle", "A-DONATION-CAPTURE",
                "--out", str(out_path),
            ])

            self.assertEqual(
                result.returncode, 0,
                f"expected exit 0; stderr={result.stderr!r}",
            )
            # Harness bootstrapped from tools/invariants/families/vault/.
            self.assertTrue(
                harness_dest.is_file(),
                f"expected harness at {harness_dest}; dir contents: "
                f"{list((bundle / 'harnesses').iterdir()) if (bundle / 'harnesses').is_dir() else 'missing'}",
            )
            # Harness content is non-empty (copied from family template).
            self.assertGreater(len(harness_dest.read_text()), 0)

            # Manifest written + advisory-only flags preserved.
            self.assertTrue(out_path.is_file())
            manifest = json.loads(out_path.read_text())
            self.assertTrue(manifest["advisory"])
            self.assertFalse(manifest["severity_upgrade_allowed"])
            self.assertFalse(manifest["evidence_matrix_contributes"])

    # ------------------------------------------------------------------
    # 2. Unmapped angle → exit 2, manifest status=error, reason cites it.
    # ------------------------------------------------------------------
    def test_force_angle_rejects_unmapped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _make_bundle(Path(tmp))
            out_path = bundle / "econ-simulator" / "A-DONATION-CAPTURE.json"

            # Precondition: sanity-check that angle_map.json does NOT list
            # A-FOOBAR (regression guard: if someone ever adds it, this
            # test needs a new unmapped angle).
            raw_map = json.loads(ANGLE_MAP.read_text())
            self.assertNotIn(
                "A-FOOBAR", raw_map,
                "test uses A-FOOBAR as the 'unmapped' fixture; "
                "it must NOT be present in tools/angle_map.json",
            )

            result = _run_sim([
                "--bundle", str(bundle),
                # --angle must be a KNOWN_ANGLE to reach the force-angle
                # branch (otherwise the earlier unknown-angle guard fires).
                # We set --force-angle to the unmapped value.
                "--angle", "A-DONATION-CAPTURE",
                "--force-angle", "A-FOOBAR",
                "--out", str(out_path),
            ])

            self.assertEqual(
                result.returncode, 2,
                f"expected exit 2 on unmapped --force-angle; "
                f"stdout={result.stdout!r} stderr={result.stderr!r}",
            )
            # Manifest emitted, status=error, reason cites unmapped angle.
            self.assertTrue(out_path.is_file())
            manifest = json.loads(out_path.read_text())
            self.assertEqual(manifest["status"], "error")
            self.assertIn("A-FOOBAR", manifest["reason"])
            self.assertIn("angle_map.json", manifest["reason"])
            # Advisory-only flags still preserved on the error path.
            self.assertTrue(manifest["advisory"])
            self.assertFalse(manifest["severity_upgrade_allowed"])
            self.assertFalse(manifest["evidence_matrix_contributes"])

    # ------------------------------------------------------------------
    # 3. Provenance field `angle_source: "force-angle-cli"` recorded.
    # ------------------------------------------------------------------
    def test_force_angle_records_provenance_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _make_bundle(Path(tmp))
            out_path = bundle / "econ-simulator" / "A-DONATION-CAPTURE.json"

            result = _run_sim([
                "--bundle", str(bundle),
                "--angle", "A-DONATION-CAPTURE",
                "--force-angle", "A-DONATION-CAPTURE",
                "--out", str(out_path),
            ])

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(out_path.is_file())
            manifest = json.loads(out_path.read_text())
            self.assertEqual(
                manifest.get("angle_source"),
                "force-angle-cli",
                f"expected angle_source='force-angle-cli' in manifest; "
                f"got {manifest.get('angle_source')!r}",
            )

            # Locked-vocab regression guard: `status` must stay inside
            # ALLOWED_STATUSES. `angle_source` is a PROVENANCE field, NOT
            # a status string — it must never appear in the `status` slot.
            allowed_statuses = {
                "pass", "counterexample", "no-counterexample",
                "timeout", "error", "skipped",
            }
            self.assertIn(manifest["status"], allowed_statuses)
            self.assertNotEqual(manifest["status"], "force-angle-cli")


if __name__ == "__main__":
    unittest.main()
