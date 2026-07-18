#!/usr/bin/env python3
"""test_audit_deep_skip_audit_prereq.py - regression test for the
AUDIT_DEEP_SKIP_AUDIT_PREREQ env-var escape hatch on the `audit-deep`
Makefile target (L23 ABK fix).

Background:
  ABG L22 documented that `make audit-deep WS=~/audits/spark` HARD STOPs at
  `pre-iter-check.sh` step 7 ("SESSION_LOG.md has no iteration index table")
  for paste-ready-driven workspaces (Spark engagement runs Go-runtime PoCs
  outside the canonical engage.py iteration loop). The L23 ABK fix adds the
  AUDIT_DEEP_SKIP_AUDIT_PREREQ=1 env var that, when set, drops the `audit`
  prerequisite from the audit-deep target so `tools/audit-deep.sh` is
  reachable directly via the Makefile path.

Asserted behaviors:
  1. The Makefile contains the `_AUDIT_DEEP_PREREQ` macro that gates the
     prerequisite on the env var.
  2. The Makefile recipe prints the bypass-banner only when the env var is
     set (default-OFF check).
  3. With AUDIT_DEEP_SKIP_AUDIT_PREREQ=1, `make -n audit-deep WS=<sandbox>`
     does NOT plan to run the `audit` recipe.
  4. Without the env var, `make -n audit-deep WS=<sandbox>` DOES plan the
     `audit` recipe (default-OFF preserved).

Discipline:
  - Stdlib only. No new pip deps.
  - Skips cleanly if make/bash unavailable.
  - Sandbox HOME so the test can't pollute the real workspace tree.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
MAKEFILE = REPO / "Makefile"


class TestAuditDeepSkipAuditPrereq(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("make"):
            raise unittest.SkipTest("make not on PATH")
        if not shutil.which("bash"):
            raise unittest.SkipTest("bash not on PATH")
        if not MAKEFILE.is_file():
            raise unittest.SkipTest(f"{MAKEFILE} not found")

    def setUp(self):
        # Sandbox HOME so any side effects from `make -n` (like _WS_RESOLVED
        # tilde expansion) don't escape into the real ~/audits tree.
        self.sandbox = Path(tempfile.mkdtemp(prefix="test_audit_deep_skip_"))
        self.ws = self.sandbox / "audits" / "skip-prereq-test"
        self.ws.mkdir(parents=True, exist_ok=True)
        # Minimal scaffold so _WS_RESOLVED resolves to a real directory; the
        # `[ ! -d "$(_WS_RESOLVED)" ]` guard inside the `audit` recipe would
        # otherwise reject a missing workspace before the dry-run finishes
        # parsing the recipe. We do not need SESSION_LOG / SCOPE etc. because
        # `make -n` does NOT execute the recipe - it only prints planned cmds.
        (self.ws / ".audit_logs").mkdir(exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.sandbox, ignore_errors=True)

    # ----- Static Makefile assertions -----

    def test_makefile_has_prereq_macro(self):
        """The _AUDIT_DEEP_PREREQ macro must gate the prereq on the env vars.

        The macro now gates on TWO env vars:
          1. _AUDIT_DEEP_MCP_PREFLIGHT_ENABLED - if set, skips audit entirely
          2. AUDIT_DEEP_SKIP_AUDIT_PREREQ - if set, skips audit entirely

        Either one being set causes the prereq to be dropped.
        """
        text = MAKEFILE.read_text()
        self.assertIn(
            "_AUDIT_DEEP_PREREQ := $(if $(_AUDIT_DEEP_MCP_PREFLIGHT_ENABLED),,$(if $(AUDIT_DEEP_SKIP_AUDIT_PREREQ),,audit))",
            text,
            "Makefile missing _AUDIT_DEEP_PREREQ env-var-gated macro with MCP preflight layer",
        )
        self.assertIn(
            "audit-deep: $(_AUDIT_DEEP_PREREQ)",
            text,
            "audit-deep target must reference the gated macro, not raw `audit`",
        )

    def test_makefile_bypass_banner_present(self):
        """The recipe must print a clear bypass-banner when the env var fires."""
        text = MAKEFILE.read_text()
        self.assertIn("AUDIT_DEEP_SKIP_AUDIT_PREREQ", text)
        self.assertIn(
            "bypassing 'audit' prerequisite",
            text,
            "Makefile recipe missing bypass-banner; operators should see why "
            "the prerequisite was skipped",
        )

    # ----- Dry-run (`make -n`) behavioral assertions -----

    def _run_make_dry(self, env_overlay):
        env = os.environ.copy()
        env["HOME"] = str(self.sandbox)
        env.update(env_overlay)
        # `make -n` prints the recipe commands without executing them; the
        # prerequisite chain is still resolved, so we can check whether
        # `audit` recipe lines (the freshness guard, etc.) appear.
        proc = subprocess.run(
            [
                "make",
                "-n",
                "audit-deep",
                f"WS={self.ws}",
            ],
            cwd=str(REPO),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return proc

    def test_env_var_set_drops_audit_prereq(self):
        """With AUDIT_DEEP_SKIP_AUDIT_PREREQ=1, `audit` is NOT planned."""
        proc = self._run_make_dry({"AUDIT_DEEP_SKIP_AUDIT_PREREQ": "1"})
        self.assertEqual(
            proc.returncode,
            0,
            f"make -n exit nonzero: {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )
        # The audit-stage marker check (a hallmark of the canonical `audit`
        # recipe body) should NOT appear when the prereq is skipped.
        # The unique signature is "audit-completion-marker.py check" -
        # specific to the audit recipe's freshness guard.
        self.assertNotIn(
            "audit-completion-marker.py check",
            proc.stdout,
            "audit prerequisite executed despite escape-hatch env var; "
            "the macro must drop the prereq when env is set",
        )
        # When env is set, the printed bypass-banner guard expands to
        # `if [ -n "1" ]` (truthy at runtime). We can detect this via the
        # rendered echo argument since make expands $(AUDIT_DEEP_SKIP_AUDIT_PREREQ).
        self.assertIn(
            "AUDIT_DEEP_SKIP_AUDIT_PREREQ=1 - bypassing",
            proc.stdout,
            "expanded bypass banner not visible in make -n output despite "
            "env var set; macro expansion may be wrong",
        )
        # `bash tools/audit-deep.sh` must still appear in the plan (the deep
        # aggregator itself MUST run; we are only skipping the prereq chain).
        self.assertIn(
            "bash tools/audit-deep.sh",
            proc.stdout,
            "audit-deep recipe body missing - the escape hatch must keep "
            "the deep aggregator runnable",
        )

    def test_env_var_unset_keeps_audit_prereq(self):
        """Without the env var, `audit` recipe IS planned (default-OFF)."""
        # Explicitly unset the env var even if it leaked in from CI.
        env_overlay = {}
        if "AUDIT_DEEP_SKIP_AUDIT_PREREQ" in os.environ:
            env_overlay["AUDIT_DEEP_SKIP_AUDIT_PREREQ"] = ""
        proc = self._run_make_dry(env_overlay)
        # The audit recipe MUST be planned; absence of this string would
        # mean the macro accidentally treated empty-string as truthy and
        # dropped the prereq.
        self.assertIn(
            "audit-completion-marker.py check",
            proc.stdout,
            "audit prerequisite NOT planned even though escape-hatch was "
            "OFF - default-OFF behavior regressed:\n" + proc.stdout[:2000],
        )
        # Banner-guard expansion sanity: when env is unset, the printed
        # recipe's banner guard expands to `if [ -n "" ]`, which would NOT
        # echo at runtime. The expanded `AUDIT_DEEP_SKIP_AUDIT_PREREQ=` (empty
        # value) string differentiates from the env-set case.
        self.assertNotIn(
            "AUDIT_DEEP_SKIP_AUDIT_PREREQ=1 - bypassing",
            proc.stdout,
            "expanded bypass banner with =1 leaked even though env var was "
            "unset; the macro may not be respecting the unset state",
        )


if __name__ == "__main__":
    unittest.main()
