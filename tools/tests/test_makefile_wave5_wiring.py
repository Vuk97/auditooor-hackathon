"""Guard: wave-5 Makefile wiring for the completeness-matrix per-file STRICT export
and the early (step-1) guard-completeness advisory pass.

WHY (two independent prior-wave gaps, both GENERIC / all-language / all-workspace):

(1) completeness-matrix-build.py already READS AUDITOOOR_MATRIX_PERFILE_STRICT (a prior
    wave built the per-file completeness floor) but NO driver ever EXPORTED the flag, so
    the per-file floor stayed advisory forever. The audit-complete recipe has a single
    `if [ -n "$(STRICT)" ] && [ "$(STRICT)" != "0" ]` block that already exports the four
    sibling STRICT env vars (COMMIT_ADJUDICATION / MANUAL_STEP / INVARIANT_FUZZ_ASSET /
    FUZZ_TARGET). This test guards that AUDITOOOR_MATRIX_PERFILE_STRICT is exported in that
    SAME block (fifth export) so the floor only enforces when the operator opts in with
    STRICT=1 - it can never retroactively brick a prior audit run at STRICT unset/0.

(2) guard-completeness-check.py must run as part of step-1 (the EARLY structural pass,
    right after the in-scope enumeration / inscope-manifest emit) but be NON-FATAL: a
    missing/failing guard must print an advisory WARN and continue, exactly like every
    other step-1 advisory. An early guard-completeness pass must never block a prior audit.

Asserts on the recipe BLOCK for each target (target line to next top-level target line),
not the whole file, so an unrelated mention elsewhere cannot mask a regression. Mirrors
tools/tests/test_anchor_hunt_makefile_wiring.py. Also runs `make -n` dry-runs to prove
the recipe lines expand (the guard line appears exactly once, non-fatal; all FIVE STRICT
exports appear under STRICT=1).
"""
from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MAKEFILE = REPO / "Makefile"

MATRIX_STRICT_ENV = "AUDITOOOR_MATRIX_PERFILE_STRICT"
SIBLING_STRICT_ENVS = [
    "AUDITOOOR_COMMIT_ADJUDICATION_STRICT",
    "AUDITOOOR_MANUAL_STEP_STRICT",
    "AUDITOOOR_INVARIANT_FUZZ_ASSET_STRICT",
    "AUDITOOOR_FUZZ_TARGET_STRICT",
]
GUARD_TOOL = "tools/guard-completeness-check.py"
GUARD_WARN = "guard-completeness-check unavailable (non-fatal, advisory)"


def _recipe_block(text: str, target: str) -> str:
    """Return the recipe body for `target:` up to (not including) the next
    top-level (non-indented) target line. Mirrors test_anchor_hunt_makefile_wiring.py."""
    lines = text.splitlines()
    out: list[str] = []
    capturing = False
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


class TestMakefileWave5Wiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not MAKEFILE.is_file():
            raise unittest.SkipTest(f"{MAKEFILE} not found")
        cls.text = MAKEFILE.read_text(encoding="utf-8")
        cls.audit_complete_block = _recipe_block(cls.text, "audit-complete")
        cls.audit_block = _recipe_block(cls.text, "audit")

    # ---- static recipe-body parse: edit (1) matrix-perfile STRICT export --------------

    def test_matrix_strict_export_present_in_audit_complete(self) -> None:
        self.assertIn(
            f"export {MATRIX_STRICT_ENV}=1",
            self.audit_complete_block,
            f"{MATRIX_STRICT_ENV}=1 must be exported in the audit-complete recipe",
        )

    def test_matrix_strict_export_in_the_existing_strict_block(self) -> None:
        """The fifth export must live in the SAME `if [ -n "$(STRICT)" ]...` block as the
        four siblings - not a second block. Verify all five exports appear between the
        STRICT-guard `if` and its matching `fi`, and that there is exactly one such block."""
        block = self.audit_complete_block
        guard_if = 'if [ -n "$(STRICT)" ] && [ "$(STRICT)" != "0" ]; then'
        self.assertEqual(
            block.count(guard_if),
            1,
            "expected exactly ONE STRICT-guard if-block in audit-complete (no second block)",
        )
        start = block.index(guard_if)
        # matching `fi` for this block: the last `fi` in the recipe body
        fi_idx = block.rindex("\n\tfi")
        self.assertGreater(fi_idx, start, "could not locate matching fi for the STRICT block")
        inner = block[start:fi_idx]
        for env in SIBLING_STRICT_ENVS + [MATRIX_STRICT_ENV]:
            self.assertIn(
                f"export {env}=1",
                inner,
                f"{env}=1 must be exported inside the single STRICT-guard block",
            )

    def test_matrix_strict_not_exported_unconditionally(self) -> None:
        """Guard the opt-in contract: the export must be gated behind STRICT, never a bare
        top-level export that would enforce the per-file floor on every audit."""
        # The only occurrence(s) of the export must be indented under the if-block (a
        # continued-shell line starts with a tab + spaces). There must be no line that is
        # `export AUDITOOOR_MATRIX_PERFILE_STRICT=1` outside a STRICT-gated context.
        occurrences = self.audit_complete_block.count(f"export {MATRIX_STRICT_ENV}=1")
        self.assertEqual(occurrences, 1, "matrix STRICT export should appear exactly once")

    # ---- static recipe-body parse: edit (2) early guard-completeness advisory ----------

    def test_guard_completeness_invoked_in_audit_step1(self) -> None:
        self.assertIn(
            GUARD_TOOL,
            self.audit_block,
            f"{GUARD_TOOL} must be invoked in the step-1 `audit` recipe",
        )

    def test_guard_completeness_is_non_fatal(self) -> None:
        """The invocation must be advisory: guarded with `|| echo ... continuing` so a
        missing/failing guard can never block a prior audit."""
        block = self.audit_block
        # locate the guard invocation line and assert it has the `|| echo ...` fallback.
        found = False
        for ln in block.splitlines():
            if GUARD_TOOL in ln:
                self.assertIn("|| echo", ln, "guard-completeness line must have `|| echo` fallback")
                self.assertIn(GUARD_WARN, ln, "guard fallback must print the advisory WARN")
                self.assertIn("continuing", ln, "guard fallback must state it is continuing")
                found = True
        self.assertTrue(found, "guard-completeness invocation line not found in audit block")

    def test_guard_completeness_uses_resolved_ws_var(self) -> None:
        """Must use the same WS variable the audit recipe already uses (_WS_RESOLVED),
        never a hardcoded path or a raw $(WS)."""
        block = self.audit_block
        for ln in block.splitlines():
            if GUARD_TOOL in ln:
                self.assertIn("$(_WS_RESOLVED)", ln, "guard must use $(_WS_RESOLVED)")

    def test_no_dashes(self) -> None:
        """No em-dashes / en-dashes in the two edited recipe lines."""
        for env_line in [f"export {MATRIX_STRICT_ENV}=1"]:
            for ln in self.audit_complete_block.splitlines():
                if env_line in ln:
                    self.assertNotIn("—", ln)
                    self.assertNotIn("–", ln)
        for ln in self.audit_block.splitlines():
            if GUARD_TOOL in ln:
                self.assertNotIn("—", ln)
                self.assertNotIn("–", ln)

    # ---- dry-run expansion (make -n) proves the recipe lines are reachable -------------

    def test_make_n_audit_complete_shows_five_exports(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            proc = subprocess.run(
                ["make", "-n", "audit-complete", f"WS={td}", "STRICT=1"],
                cwd=str(REPO),
                capture_output=True,
                text=True,
            )
        out = proc.stdout + proc.stderr
        for env in SIBLING_STRICT_ENVS + [MATRIX_STRICT_ENV]:
            self.assertIn(
                f"export {env}=1",
                out,
                f"`make -n audit-complete STRICT=1` must emit export {env}=1",
            )

    def test_make_n_audit_shows_guard_line_non_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            proc = subprocess.run(
                ["make", "-n", "audit", f"WS={td}"],
                cwd=str(REPO),
                capture_output=True,
                text=True,
            )
        out = proc.stdout + proc.stderr
        self.assertIn(GUARD_TOOL, out, "`make -n audit` must emit the guard-completeness line")
        # The emitted guard line must carry the non-fatal `|| echo ... continuing` fallback.
        guard_lines = [ln for ln in out.splitlines() if GUARD_TOOL in ln]
        self.assertTrue(guard_lines, "no guard-completeness line in `make -n audit` output")
        self.assertTrue(
            any("|| echo" in ln and "continuing" in ln for ln in guard_lines),
            "the emitted guard-completeness line must be non-fatal (|| echo ... continuing)",
        )


if __name__ == "__main__":
    unittest.main()
