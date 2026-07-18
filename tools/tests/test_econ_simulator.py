#!/usr/bin/env python3
"""PR 207 iter4 T4 — economic-simulator prototype smoke tests.

Offline; stdlib-only. No real halmos/anvil/RPC invocation. Four tests:

  1. `test_dry_run_emits_scaffolded_manifest` — the default invocation
     writes `<bundle>/econ-simulator/<angle>.json` with
     `status: skipped`, `reason: "dry-run: scaffolded"`. Never `pass`.

  2. `test_unknown_angle_returns_error_not_pass` — `--angle A-FOOBAR`
     returns nonzero exit and writes a `status: error` manifest. No
     silent pass under any circumstances.

  3. `test_simulator_output_is_advisory_only_never_proof` — feeds a
     `status: skipped` simulator manifest into `build_evidence_matrix()`
     (imported from `tools/submission-packager.py`). Asserts the matrix
     does NOT mark `evidence-matrix.verdict = READY` solely on the
     strength of the simulator output. The simulator's manifest is
     classified as `advisory` / non-PROOF — the matrix's `symbolic` row
     stays `N/A` (the existing Phase-C pending slot), and no new
     `econ_simulator` row is promoted to PRESENT.

  4. `test_simulator_cannot_upgrade_severity` — with a Medium draft and a
     simulated `counterexample` manifest (hand-crafted to probe the
     hard-negative), assert the repackaged bundle's severity stays
     Medium. Simulator output cannot be used to upgrade severity.

All tests run fully offline; no subprocess spawns reach network or any
real symbolic engine.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "econ-simulator.py"
PACKAGER_PATH = ROOT / "tools" / "submission-packager.py"


def _load_packager_module():
    spec = importlib.util.spec_from_file_location(
        "submission_packager", PACKAGER_PATH,
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _run_sim(args, *, env=None):
    """Invoke econ-simulator.py with a clean env; always dry-run by default."""
    run_env = os.environ.copy()
    # Pin dry-run by default. Individual tests override with env={"ECON_SIM_DRY_RUN": "0"}.
    run_env.setdefault("ECON_SIM_DRY_RUN", "1")
    if env:
        run_env.update(env)
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=ROOT, env=run_env, capture_output=True, text=True,
    )


def _make_bundle(tmp: Path, severity: str = "Medium") -> Path:
    """Build a minimal packaged-bundle skeleton for testing.

    Mirrors the shape of `~/audits/polymarket/submissions/packaged/r77-06/`:
    a `source-draft.md`, an `evidence-matrix.json`, and a `manifest.json`.
    Only the fields the simulator + build_evidence_matrix actually read
    are populated.
    """
    bundle = tmp / "packaged" / "r77-06"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "source-draft.md").write_text(
        "## Test finding\n"
        f"**Severity**: {severity}\n\n"
        "Target: `CtfCollateralAdapter` — balance-delta defect.\n"
    )
    (bundle / "evidence-matrix.json").write_text(json.dumps({
        "schema_version": 1,
        "severity": severity.upper(),
        "rows": [],
        "summary": {"ready_verdict": "UNKNOWN"},
    }, indent=2))
    (bundle / "manifest.json").write_text(json.dumps({
        "workspace": "polymarket",
    }, indent=2))
    return bundle


class EconSimulatorTest(unittest.TestCase):

    # ------------------------------------------------------------------
    # 1. Dry-run emits a scaffolded manifest.
    # ------------------------------------------------------------------
    def test_dry_run_emits_scaffolded_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _make_bundle(Path(tmp))

            proc = _run_sim([
                "--bundle", str(bundle),
                "--angle", "A-DONATION-CAPTURE",
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest_path = bundle / "econ-simulator" / "A-DONATION-CAPTURE.json"
            self.assertTrue(manifest_path.exists(), proc.stderr)

            payload = json.loads(manifest_path.read_text())
            # Status vocabulary lock — must be exactly `skipped`, never pass.
            self.assertEqual(payload["status"], "skipped")
            self.assertNotEqual(payload["status"], "pass")
            self.assertRegex(payload.get("reason", ""), r"dry-run")
            self.assertEqual(payload["angle"], "A-DONATION-CAPTURE")
            self.assertEqual(payload["prototype_target"], "POLY-ITER3-R77-06")
            self.assertTrue(payload["advisory"])
            # Hard-negative flags — these must be serialised into every
            # advisory manifest so downstream consumers can never mistake
            # the simulator for a proof-grade contributor.
            self.assertFalse(payload["severity_upgrade_allowed"])
            self.assertFalse(payload["evidence_matrix_contributes"])
            # Bundle-anchored output location (hard rule).
            self.assertEqual(manifest_path.parent, bundle / "econ-simulator")
            # Doctrine note is present and cites WORKFLOW.md.
            self.assertIn("WORKFLOW.md", payload.get("notes", ""))

            # The simulator must NEVER modify the bundle's evidence-matrix.
            em_after = json.loads((bundle / "evidence-matrix.json").read_text())
            self.assertEqual(em_after["summary"]["ready_verdict"], "UNKNOWN")

    # ------------------------------------------------------------------
    # 2. Unknown angle → status=error + nonzero exit.
    # ------------------------------------------------------------------
    def test_unknown_angle_returns_error_not_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _make_bundle(Path(tmp))

            proc = _run_sim([
                "--bundle", str(bundle),
                "--angle", "A-FOOBAR",
            ])
            # Misconfiguration — non-zero exit required.
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("unknown --angle", proc.stderr)

            manifest_path = bundle / "econ-simulator" / "A-FOOBAR.json"
            self.assertTrue(
                manifest_path.exists(),
                "error manifest must be written for unknown angle",
            )
            payload = json.loads(manifest_path.read_text())
            # Status must be error, never silent pass.
            self.assertEqual(payload["status"], "error")
            self.assertNotEqual(payload["status"], "pass")
            self.assertEqual(payload["angle"], "A-FOOBAR")
            self.assertTrue(payload["advisory"])
            self.assertFalse(payload["severity_upgrade_allowed"])
            self.assertFalse(payload["evidence_matrix_contributes"])

    # ------------------------------------------------------------------
    # 3. Simulator output is advisory-only — never proof-grade.
    # ------------------------------------------------------------------
    def test_simulator_output_is_advisory_only_never_proof(self) -> None:
        """The simulator manifest is not allowed to promote the evidence
        matrix to READY purely on its own strength.

        We construct a `results` dict that is pessimistic on every
        proof-grade row EXCEPT the simulator's advisory output, then call
        `build_evidence_matrix()` and assert the verdict is NOT READY."""
        pkg = _load_packager_module()
        build_evidence_matrix = pkg.build_evidence_matrix

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bundle = _make_bundle(tmp_path, severity="High")

            # Run the simulator to generate a real scaffolded manifest.
            proc = _run_sim([
                "--bundle", str(bundle),
                "--angle", "A-DONATION-CAPTURE",
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            sim_manifest_path = bundle / "econ-simulator" / "A-DONATION-CAPTURE.json"
            sim_manifest = json.loads(sim_manifest_path.read_text())
            self.assertEqual(sim_manifest["status"], "skipped")

            # Build a results dict where ALL proof-grade rows are MISSING /
            # unreferenced, so the ONLY piece of "evidence" available is the
            # advisory simulator manifest. If the packager were accidentally
            # to trust the simulator, this would go READY.
            results = {
                "gates": {
                    "variant": {"risk_level": "LOW"},
                    "pre_submit": {"rc": 0, "output": "  ✅ 20. ok\n"},
                },
                "fork_replay": {"entries": [], "missing": [], "malformed": []},
                "live_proof": {
                    "proof_status": "missing",
                    "referenced_ids": [],
                },
                # Simulator output surfaced — packager must NOT promote on it.
                "econ_simulator": {"manifest": sim_manifest},
            }

            draft = bundle / "source-draft.md"
            matrix = build_evidence_matrix(
                results, draft_path=draft, ws=tmp_path, poc_found=False,
            )

            # The advisory simulator manifest must NOT flip verdict to READY.
            verdict = matrix["summary"]["ready_verdict"]
            self.assertNotEqual(
                verdict, "READY",
                "evidence-matrix verdict was promoted to READY off the "
                "advisory simulator manifest alone — violates PR 207 "
                "scaffolding-only contract",
            )
            # Verdict must also not be PROOF (not in the locked vocab anyway).
            self.assertNotIn(verdict, {"PROOF", "SIMULATED"})

            # The matrix exposes rows keyed by short name. The simulator
            # must not inject a PRESENT row via a side-channel: any row
            # whose key mentions `econ` or `sim` must not be PRESENT.
            for row in matrix.get("rows", []):
                key = str(row.get("key", "")).lower()
                if "econ" in key or "sim" in key:
                    self.assertNotEqual(
                        row.get("status"), "PRESENT",
                        f"simulator-related row {key!r} was promoted to "
                        f"PRESENT off a status=skipped manifest",
                    )

            # Defense-in-depth: assert the simulator manifest still carries
            # the advisory flags that downstream consumers key off.
            self.assertTrue(sim_manifest["advisory"])
            self.assertFalse(sim_manifest["severity_upgrade_allowed"])
            self.assertFalse(sim_manifest["evidence_matrix_contributes"])

    # ------------------------------------------------------------------
    # 4. Simulator output cannot upgrade a Medium draft's severity.
    # ------------------------------------------------------------------
    def test_simulator_cannot_upgrade_severity(self) -> None:
        """Hand-forge a `status: counterexample` manifest (worst-case) and
        feed it through the evidence-matrix path for a Medium draft.

        The matrix's `severity` field is derived from the draft text, NOT
        from the simulator output; asserting the severity stays Medium is
        the hard-negative lock against future regressions that might
        accidentally thread the simulator into the severity inference
        path."""
        pkg = _load_packager_module()
        build_evidence_matrix = pkg.build_evidence_matrix

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bundle = _make_bundle(tmp_path, severity="Medium")
            draft = bundle / "source-draft.md"

            # Manually craft a counterexample-status manifest (locked
            # vocab). In the real pipeline this is what a live halmos/
            # anvil counterexample would eventually produce, but iter4's
            # `--live` path hard-stops with status=error. We fabricate the
            # counterexample payload here *just* to probe the matrix's
            # severity logic — the fabricated file is NOT written to the
            # bundle's econ-simulator/ output dir (only `results` sees it).
            forged_ce = {
                "schema_version": 1,
                "pr": 207,
                "tool": "econ-simulator",
                "angle": "A-DONATION-CAPTURE",
                "status": "counterexample",
                "reason": "FORGED counterexample — test probe, not real",
                "advisory": True,
                "severity_upgrade_allowed": False,
                "evidence_matrix_contributes": False,
            }

            results = {
                "gates": {
                    "variant": {"risk_level": "LOW"},
                    "pre_submit": {"rc": 0, "output": "  ✅ 20. ok\n"},
                },
                "fork_replay": {"entries": [], "missing": [], "malformed": []},
                "live_proof": {"proof_status": "not-required",
                               "referenced_ids": []},
                "econ_simulator": {"manifest": forged_ce},
            }

            matrix = build_evidence_matrix(
                results, draft_path=draft, ws=tmp_path, poc_found=True,
            )

            # Severity MUST stay MEDIUM — simulator manifests cannot move it.
            self.assertEqual(
                matrix["severity"], "MEDIUM",
                "draft severity was upgraded off the simulator manifest — "
                "violates PR 207 advisory-only contract",
            )
            # Also verify the draft itself on disk still reads Medium.
            self.assertIn(
                "**Severity**: Medium",
                draft.read_text(),
                "simulator invocation must never edit the source draft",
            )
            # And the bundle's evidence-matrix.json on disk is still the
            # placeholder we wrote — the simulator test never touched it.
            em_on_disk = json.loads((bundle / "evidence-matrix.json").read_text())
            self.assertEqual(em_on_disk["severity"], "MEDIUM")


if __name__ == "__main__":
    unittest.main(verbosity=2)
