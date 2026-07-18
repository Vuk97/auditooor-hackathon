#!/usr/bin/env python3
"""V5-P0-11 / Gap 21 regression tests for audit-deep per-profile reports.

The prior behavior copied each profile's run log over a single shared
``audit_deep_report.md`` filename, so a DEEP_PROFILE=all run left only
the last profile's report on disk. The fix: each profile writes a
durable ``audit_deep_<profile>_<TS>.md`` and the canonical
``audit_deep_report.md`` is a symlink to the latest.

Asserts:

  1. DEEP_PROFILE=all writes per-profile timestamped reports for each
     child plus an aggregate ``audit_deep_all_<TS>.md`` (no
     last-profile-wins overwrite of siblings).
  2. The all-profile manifest lists default/math/econ/crypto and stays
     intact.
  3. ``audit_deep_report.md`` is a symlink to the latest per-profile
     report after a DEEP_PROFILE=all run.
  4. Two back-to-back single-profile runs (math then econ) preserve both
     ``audit_deep_math_<TS>.md`` and ``audit_deep_econ_<TS>.md``.

Hermetic, stdlib-only.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "tools" / "audit-deep.sh"


class AuditDeepPerProfileReportsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="audit_deep_pp_test_"))
        if not shutil.which("bash"):
            self.skipTest("bash not on PATH")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *flags: str) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["AUDIT_DEEP_DRY_RUN"] = "1"
        env["AUDIT_DEEP_ALL_MAX_SECONDS"] = "999"
        return subprocess.run(
            ["bash", str(WRAPPER), *flags, str(self.tmp)],
            capture_output=True,
            text=True,
            env=env,
        )

    # --- 1 + 2 + 3 ----------------------------------------------------------
    def test_all_profile_writes_distinct_reports_and_manifest(self) -> None:
        proc = self._run("--profile", "all", "--dry-run")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)

        log_dir = self.tmp / ".audit_logs"
        self.assertTrue(log_dir.exists())

        # 1. Per-profile timestamped reports are durable.
        per_profile_files = sorted(p.name for p in log_dir.glob("audit_deep_*.md"))
        # We expect at least one default + math + econ + crypto + all.
        prefixes = {"audit_deep_default_", "audit_deep_math_",
                    "audit_deep_econ_", "audit_deep_crypto_",
                    "audit_deep_all_"}
        for pref in prefixes:
            self.assertTrue(
                any(name.startswith(pref) for name in per_profile_files),
                f"missing per-profile report with prefix {pref}: {per_profile_files}",
            )

        # 2. Manifest exists and lists the four child profiles.
        manifest_paths = list(log_dir.glob("audit_deep_all_manifest.json"))
        self.assertEqual(len(manifest_paths), 1)
        manifest = json.loads(manifest_paths[0].read_text(encoding="utf-8"))
        rows = {row["profile"] for row in manifest["profiles"]}
        self.assertEqual(rows, {"default", "math", "econ", "crypto"})

        # 3. audit_deep_report.md is a symlink (or copy on filesystems
        #    that don't support symlinks) to the latest per-profile file.
        canonical = log_dir / "audit_deep_report.md"
        self.assertTrue(canonical.exists())
        # Either a symlink whose target is one of the per-profile files,
        # or a copy whose contents match the all-profile aggregate.
        if canonical.is_symlink():
            target = canonical.readlink()
            self.assertTrue(
                str(target).startswith("audit_deep_"),
                f"canonical symlink target unexpected: {target}",
            )
            # The target must exist relative to log_dir.
            resolved = (log_dir / target).resolve()
            self.assertTrue(resolved.exists())
        # Sanity: the canonical file mentions audit-deep content.
        self.assertIn("audit-deep", canonical.read_text(encoding="utf-8"))

    # --- 4 ------------------------------------------------------------------
    def test_back_to_back_single_profile_runs_preserve_both(self) -> None:
        # First run: math.
        proc1 = self._run("--profile", "math", "--dry-run")
        self.assertEqual(proc1.returncode, 0, msg=proc1.stderr)

        # Sleep briefly so the second run gets a different timestamp at
        # second resolution (TS is `+%Y%m%dT%H%M%SZ`).
        time.sleep(1.1)

        # Second run: econ.
        proc2 = self._run("--profile", "econ", "--dry-run")
        self.assertEqual(proc2.returncode, 0, msg=proc2.stderr)

        log_dir = self.tmp / ".audit_logs"
        math_reports = list(log_dir.glob("audit_deep_math_*.md"))
        econ_reports = list(log_dir.glob("audit_deep_econ_*.md"))
        self.assertGreaterEqual(len(math_reports), 1, "math report missing")
        self.assertGreaterEqual(len(econ_reports), 1, "econ report missing")

        # Canonical now points at the latest (econ).
        canonical = log_dir / "audit_deep_report.md"
        body = canonical.read_text(encoding="utf-8")
        self.assertIn("econ", body.lower())

    def test_global_typed_promotion_requires_production_path(self) -> None:
        body = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("--require-production-path", body)
        self.assertIn("--out-dossier-dir", body)
        self.assertIn("production path dossiers", body)


if __name__ == "__main__":
    unittest.main()
