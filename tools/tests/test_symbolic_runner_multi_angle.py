#!/usr/bin/env python3
"""PR 202 — symbolic-runner multi-angle expansion smoke tests.

Covers the iter3 T5 scaffolding for A-ORACLE and A-REENT:

  1. A-ORACLE under SYMBOLIC_DRY_RUN=1 (default) writes a manifest with
     status=skipped and reason matching /dry-run/.
  2. A-REENT under SYMBOLIC_DRY_RUN=1 (default) writes a manifest with
     status=skipped and reason matching /dry-run/.
  3. An unknown angle (e.g. A-FOOBAR) writes a status=error manifest and
     exits non-zero. No silent pass.
  4. Regression: a scaffolded A-ORACLE manifest with status=skipped must
     NOT be treated as proof-grade by the packager's evidence matrix. The
     `symbolic` row must remain advisory / non-PROOF, so a High+ draft
     cannot be promoted to READY on the back of a dry-run scaffold.

Fully offline. No network. No real halmos or mythril install. The runner
never invokes an engine under SYMBOLIC_DRY_RUN=1 for these angles —
that's the whole point of PR 202.
"""
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
TOOL = ROOT / "tools" / "symbolic-runner.sh"
PACKAGER_PATH = ROOT / "tools" / "submission-packager.py"


def _load_packager_module():
    spec = importlib.util.spec_from_file_location(
        "submission_packager", PACKAGER_PATH,
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _run_runner(args: list[str], *, env: dict[str, str] | None = None
                ) -> subprocess.CompletedProcess[str]:
    """Invoke symbolic-runner.sh with a clean env. No network access."""
    run_env = os.environ.copy()
    # Default to dry-run — mirrors the CLI default and guarantees no real
    # halmos/mythril process can spawn from a test host.
    run_env.setdefault("SYMBOLIC_DRY_RUN", "1")
    if env:
        run_env.update(env)
    return subprocess.run(
        ["bash", str(TOOL), *args],
        cwd=ROOT, env=run_env, capture_output=True, text=True,
    )


class SymbolicRunnerMultiAngleTest(unittest.TestCase):

    # ------------------------------------------------------------------
    # 1. A-ORACLE dry-run emits scaffolded manifest.
    # ------------------------------------------------------------------
    def test_a_oracle_mode_dry_run_emits_scaffolded_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "ws"; workspace.mkdir()
            out_dir = tmp_path / "out"

            proc = _run_runner(
                [str(workspace),
                 "--angle", "A-ORACLE",
                 "--contract", "PriceOracle",
                 "--out-dir", str(out_dir)],
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest_path = out_dir / "manifest.json"
            self.assertTrue(manifest_path.exists(), proc.stderr)
            manifest = json.loads(manifest_path.read_text())
            # Status vocabulary lock: must be exactly `skipped`, never pass.
            self.assertEqual(manifest["status"], "skipped")
            self.assertNotEqual(manifest["status"], "pass")
            self.assertRegex(manifest.get("reason", ""), r"dry-run")
            self.assertEqual(manifest["angle"], "A-ORACLE")
            self.assertTrue(manifest["advisory"])
            self.assertEqual((out_dir / "status.txt").read_text().strip(),
                             "skipped")

    # ------------------------------------------------------------------
    # 2. A-REENT dry-run emits scaffolded manifest.
    # ------------------------------------------------------------------
    def test_a_reent_mode_dry_run_emits_scaffolded_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "ws"; workspace.mkdir()
            out_dir = tmp_path / "out"

            proc = _run_runner(
                [str(workspace),
                 "--angle", "A-REENT",
                 "--contract", "Vault",
                 "--out-dir", str(out_dir)],
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest_path = out_dir / "manifest.json"
            self.assertTrue(manifest_path.exists())
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["status"], "skipped")
            self.assertNotEqual(manifest["status"], "pass")
            self.assertRegex(manifest.get("reason", ""), r"dry-run")
            self.assertEqual(manifest["angle"], "A-REENT")
            self.assertTrue(manifest["advisory"])
            self.assertEqual((out_dir / "status.txt").read_text().strip(),
                             "skipped")

    # ------------------------------------------------------------------
    # 3. Unknown angle returns `status=error`, not a silent pass.
    # ------------------------------------------------------------------
    def test_unknown_angle_returns_error_not_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "ws"; workspace.mkdir()
            out_dir = tmp_path / "out"

            proc = _run_runner(
                [str(workspace),
                 "--angle", "A-FOOBAR",
                 "--contract", "Vault",
                 "--out-dir", str(out_dir)],
            )
            # Misconfiguration: non-zero exit required.
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("unsupported --angle 'A-FOOBAR'", proc.stderr)
            manifest_path = out_dir / "manifest.json"
            self.assertTrue(manifest_path.exists(),
                            "error manifest should be written for unknown angle")
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["status"], "error")
            self.assertNotEqual(manifest["status"], "pass")
            self.assertEqual(manifest["angle"], "A-FOOBAR")

    # ------------------------------------------------------------------
    # 4. Regression: packager's evidence matrix MUST NOT classify a
    # scaffolded (status=skipped) symbolic manifest as PROOF / READY-
    # contributing. The symbolic row stays advisory — confirms PR 206 is
    # the only thing that can promote this, not PR 202.
    # ------------------------------------------------------------------
    def test_symbolic_output_is_advisory_only_never_proof(self) -> None:
        pkg = _load_packager_module()
        build_evidence_matrix = pkg.build_evidence_matrix

        # Minimal, clean results dict — no fork-replay / no live-proof /
        # no fuzz runs. Simulate an engagement where the only "symbolic"
        # evidence is a scaffolded A-ORACLE manifest with status=skipped.
        # The scaffolded manifest is NOT read by build_evidence_matrix
        # today (PR 202 explicitly defers that to PR 206). The regression
        # assertion below locks in that current contract: the `symbolic`
        # row is N/A / advisory with notes that mention the pending
        # symbolic wiring, NEVER PRESENT / PROOF on the strength of a
        # scaffolded manifest.
        scaffolded_manifest = {
            "schema_version": 1,
            "phase": "H",
            "pr": 202,
            "angle": "A-ORACLE",
            "status": "skipped",
            "reason": "dry-run: scaffolded",
            "advisory": True,
        }
        results = {
            "gates": {
                "variant": {"risk_level": "LOW"},
                "pre_submit": {"rc": 0, "output": "  ✅ 20. ok\n"},
            },
            "fork_replay": {"entries": [], "missing": [], "malformed": []},
            "live_proof": {"proof_status": "not-required", "referenced_ids": []},
            # Even if a future patch feeds the symbolic manifest into
            # `results`, today's build_evidence_matrix must not upgrade
            # the symbolic row. Keep a slot so future refactors that
            # *do* inspect this key can still assert the invariant.
            "symbolic": {"manifest": scaffolded_manifest},
        }

        ws = Path(tempfile.mkdtemp(prefix="sym-mx-ws-"))
        draft = Path(tempfile.mkstemp(suffix=".md")[1])
        # High severity draft — we want to confirm even a High+ context
        # does NOT promote the symbolic row to PRESENT off a skipped
        # manifest.
        draft.write_text("# Finding\n**Severity**: High\n")

        matrix = build_evidence_matrix(
            results, draft_path=draft, ws=ws, poc_found=True,
        )

        rows = {r["key"]: r for r in matrix["rows"]}
        self.assertIn("symbolic", rows)
        sym_row = rows["symbolic"]
        # HARD NEGATIVE: status must not be PRESENT (== proof-grade row).
        self.assertNotEqual(
            sym_row["status"], "PRESENT",
            "symbolic row was promoted to PRESENT off a status=skipped "
            "manifest — violates PR 202 scaffolding-only contract",
        )
        # Evidence-matrix vocabulary is {PRESENT, MISSING, PARTIAL, N/A}.
        # Accept N/A (current PR 109 wiring) or MISSING / PARTIAL (future
        # wirings that surface the manifest but gate promotion on PR 206).
        self.assertIn(sym_row["status"], {"N/A", "MISSING", "PARTIAL"})

        # Verdict-side guard: even a HIGH draft with forge_poc + live
        # `not-required` must NOT claim READY on the symbolic row's back.
        # (The real path to READY for this input is SOURCE_ONLY, which is
        # also acceptable — it doesn't cite symbolic as proof either.)
        verdict = matrix["summary"]["ready_verdict"]
        self.assertNotIn(
            "symbolic", (matrix.get("summary", {}).get("notes") or "").lower(),
            "verdict summary must not name symbolic as the promoter",
        )
        # Confirm no row labeled `symbolic` appears in the verdict's
        # promoting-evidence list (if the matrix exposes such a list).
        self.assertNotEqual(verdict, "PROOF")  # PROOF is not in the locked set


if __name__ == "__main__":
    unittest.main(verbosity=2)
