"""Guard: audit-deep wires coverage-plane-build.py so it is no longer a de-facto
orphan from the drivers' perspective.

tools/coverage-plane-build.py materializes the (in-scope unit x applicable
impact-frame) coverage plane as a durable per-cell artifact
(<ws>/.auditooor/coverage_plane.jsonl + coverage_plane_summary.json). It was
proven standalone (984 real cells on a live workspace) but nothing in the
Makefile invoked it, so it never ran as part of the audit-deep driver.

This test asserts, statically on the Makefile recipe BODY (not the whole
file, so an unrelated mention elsewhere cannot mask a regression):

  1. the audit-deep recipe invokes coverage-plane-build.py with --workspace,
  2. the invocation is positioned AFTER the point where inscope_units.jsonl /
     completeness-matrix-derived artifacts are already known to exist inside
     audit-deep (i.e. after capability-coverage-matrix-build.py, which is the
     first coverage/completeness-matrix consumer in the recipe),
  3. the invocation is non-fatal: no leading error-propagating shell
     construct (no bare `&&` chain to the next command, no `--strict` flag,
     and a `||`-guarded WARN-and-continue fallback is present) -- exactly the
     same non-fatal pattern used by the pre-existing dataflow-slice /
     workspace-originality-scan advisory calls in the same recipe,
  4. `make -n audit-deep WS=<throwaway>` dry-runs cleanly (rc 0) and the dry
     run output contains the new invocation line.

Generic: no solidity/strata-specific path or workspace name is hardcoded.
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"


def _recipe_block(text: str, target: str) -> str:
    """Return the recipe body for `target:` up to (excluding) the next
    top-level (non-indented) Makefile construct line."""
    lines = text.splitlines()
    out, capturing = [], False
    for ln in lines:
        if ln.startswith(f"{target}:"):
            capturing = True
            out.append(ln)
            continue
        if capturing:
            if ln and not ln.startswith(("\t", " ")) and re.match(r"^[A-Za-z0-9_.-]+:", ln):
                break
            out.append(ln)
    return "\n".join(out)


class TestCoveragePlaneMakefileWiring(unittest.TestCase):
    def setUp(self):
        self.text = MAKEFILE.read_text(encoding="utf-8")
        self.block = _recipe_block(self.text, "audit-deep")
        self.assertTrue(self.block, "audit-deep recipe not found in Makefile")

    def test_coverage_plane_build_invoked_with_workspace_flag(self):
        self.assertIn(
            "tools/coverage-plane-build.py", self.block,
            "audit-deep must invoke tools/coverage-plane-build.py (was a de-facto "
            "orphan: proven standalone but never wired into any driver)",
        )
        self.assertRegex(
            self.block,
            r"coverage-plane-build\.py\s+--workspace\s+\"\$\(_WS_RESOLVED\)\"",
            "coverage-plane-build.py must be invoked with --workspace $(_WS_RESOLVED), "
            "matching the tool's documented CLI contract",
        )

    def test_invoked_after_completeness_matrix_artifacts_exist(self):
        cov_matrix_idx = self.block.find("capability-coverage-matrix-build.py")
        cov_plane_idx = self.block.find("tools/coverage-plane-build.py")
        self.assertGreater(
            cov_matrix_idx, -1,
            "capability-coverage-matrix-build.py (a completeness-matrix-derived "
            "artifact producer) not found in audit-deep recipe -- test precondition failed",
        )
        self.assertGreater(
            cov_plane_idx, -1,
            "tools/coverage-plane-build.py invocation not found in audit-deep recipe",
        )
        self.assertGreater(
            cov_plane_idx, cov_matrix_idx,
            "coverage-plane-build.py must run AFTER capability-coverage-matrix-build.py "
            "so inscope_units.jsonl / completeness-matrix artifacts already exist on disk",
        )

    def test_invocation_is_non_fatal_no_strict_flag(self):
        # Isolate just the coverage-plane-build.py command line(s): from the
        # invocation to the following WARN echo fallback line.
        idx = self.block.find("tools/coverage-plane-build.py")
        self.assertGreater(idx, -1)
        snippet = self.block[idx: idx + 400]
        first_line = snippet.splitlines()[0]

        # No --strict flag: a workspace run without opting in must never
        # regress a prior PASS to a FAIL purely from this new artifact.
        self.assertNotIn(
            "--strict", first_line,
            "coverage-plane-build.py must be invoked WITHOUT --strict inside "
            "audit-deep so it stays advisory (fail-closed behavior needs an "
            "explicit opt-in per the STRICT-propagation contract)",
        )
        # Non-fatal: guarded by `||` into a WARN-and-continue, not a bare
        # `&&`-chained command that would propagate a failure.
        self.assertIn(
            "||", snippet,
            "coverage-plane-build.py invocation must be || -guarded (non-fatal, "
            "warn-and-continue), matching the dataflow-slice / "
            "workspace-originality-scan advisory pattern used elsewhere in audit-deep",
        )
        self.assertIn(
            "WARN", snippet,
            "coverage-plane-build.py failure path must emit a WARN, not fail-close "
            "the recipe (non-fatal by default; STRICT=1 opt-in is out of scope here)",
        )

    def test_dry_run_audit_deep_includes_new_invocation_and_parses_clean(self):
        if not shutil.which("make"):
            self.skipTest("make not available on PATH")
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "throwaway_ws"
            (ws / ".auditooor").mkdir(parents=True)
            proc = subprocess.run(
                [
                    "make", "-n", "audit-deep",
                    f"WS={ws}",
                    "AUDIT_DEEP_SKIP_AUDIT_PREREQ=1",
                    "AUDIT_DEEP_ALLOW_STALE_AUDIT_PREREQ=1",
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(
                proc.returncode, 0,
                f"make -n audit-deep must parse with zero errors; stderr:\n{proc.stderr}",
            )
            self.assertIn(
                "coverage-plane-build.py", proc.stdout,
                "dry-run output must include the new coverage-plane-build.py invocation",
            )


if __name__ == "__main__":
    unittest.main()
