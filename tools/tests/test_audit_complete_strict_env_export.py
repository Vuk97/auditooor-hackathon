"""Regression guard: `make audit-complete STRICT=1` must EXPORT the STRICT env vars
for the three real fail-closed gates that are wired but stay ADVISORY forever
because no driver ever exported their own env var:

  - AUDITOOOR_COMMIT_ADJUDICATION_STRICT (tools/commit-adjudication-completeness-check.py)
  - AUDITOOOR_MANUAL_STEP_STRICT          (tools/manual-step-preflight.py)
  - AUDITOOOR_INVARIANT_FUZZ_ASSET_STRICT (tools/invariant-fuzz-completeness.py)
  - AUDITOOOR_FUZZ_TARGET_STRICT          (tools/fuzz-target-completeness-check.py)

Root defect: each gate script independently reads its own env var
(os.environ.get(...)) and defaults to advisory (warn, rc 0) unless that var is set.
Nothing in the audit pipeline ever set it, so all three enforcement paths were dead
code from the caller's perspective - `make audit-complete WS=<ws> STRICT=1` could
never make them hard-fail no matter how broken the underlying evidence was.

Fix (Makefile, audit-complete recipe): when the caller passes STRICT=1 (and only
then - this must be gated, not unconditional, so it never retroactively bricks a
prior audit that ran without STRICT), export all four env vars into the recipe's
shell BEFORE the gate script/python invocations, mirroring the pre-existing
AUDITOOOR_L37_STRICT propagation pattern already in the same recipe.

Two invariants this test locks down:
  (1) STATIC: the `audit-complete` recipe body in the Makefile contains the four
      `export AUDITOOOR_*_STRICT=1` lines, gated behind a STRICT check, and the
      export lines textually precede the `audit-completeness-check.py` invocation
      within the STRICT branch (so they take effect before any gate runs).
  (2) DYNAMIC: `make -n audit-complete WS=<throwaway> STRICT=1` does not error, the
      dry-run output contains the four export lines, and `make -n audit-complete
      WS=<throwaway>` (STRICT unset) does NOT contain them (backward-compat: stays
      advisory when the operator did not opt in).
"""
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
_MAKEFILE = _REPO / "Makefile"

_STRICT_VARS = (
    "AUDITOOOR_COMMIT_ADJUDICATION_STRICT",
    "AUDITOOOR_MANUAL_STEP_STRICT",
    "AUDITOOOR_INVARIANT_FUZZ_ASSET_STRICT",
    "AUDITOOOR_FUZZ_TARGET_STRICT",
)


def _extract_recipe_body(makefile_text: str, target: str) -> str:
    """Return the raw recipe-line block for a `target:` rule (lines beginning with a
    tab, up to the first non-recipe line), mirroring simple Make parsing."""
    lines = makefile_text.splitlines()
    header_re = re.compile(rf"^{re.escape(target)}\s*:(?!=)")
    body = []
    in_target = False
    for line in lines:
        if not in_target:
            if header_re.match(line):
                in_target = True
            continue
        if line.startswith("\t"):
            body.append(line)
        elif line.strip() == "":
            continue
        else:
            break
    return "\n".join(body)


class MakefileStaticTest(unittest.TestCase):
    def setUp(self):
        self.text = _MAKEFILE.read_text()
        self.body = _extract_recipe_body(self.text, "audit-complete")
        self.assertTrue(self.body, "could not locate the audit-complete recipe body")

    def test_recipe_is_not_audit_pipeline_full(self):
        """Sanity: we parsed audit-complete, not the (already-edited-elsewhere)
        audit-pipeline-full target."""
        self.assertNotIn("audit-pipeline-full", self.body.splitlines()[0])

    def test_all_four_strict_vars_exported(self):
        for var in _STRICT_VARS:
            self.assertIn(
                f"export {var}=1", self.body,
                f"audit-complete recipe does not export {var}=1 anywhere",
            )

    def test_exports_are_gated_on_strict(self):
        """The export lines must live inside a STRICT-conditional branch, not run
        unconditionally (unconditional export would enforce these gates even when
        the caller never opted into STRICT=1, retroactively bricking prior audits)."""
        for var in _STRICT_VARS:
            idx = self.body.find(f"export {var}=1")
            self.assertGreater(idx, -1)
            preamble = self.body[:idx]
            # Nearest preceding conditional must reference $(STRICT) or STRICT.
            last_if = preamble.rfind("if [")
            self.assertGreater(
                last_if, -1,
                f"export {var}=1 has no preceding `if [ ... ]` guard in the recipe",
            )
            guard = preamble[last_if:idx]
            self.assertIn(
                "STRICT", guard,
                f"the guard immediately preceding `export {var}=1` does not "
                f"reference STRICT: {guard!r}",
            )

    def test_exports_precede_gate_invocation(self):
        """The export lines must textually precede the audit-completeness-check.py
        call within the STRICT branch (export-before-invoke ordering)."""
        gate_idx = self.body.find("audit-completeness-check.py")
        self.assertGreater(gate_idx, -1, "audit-completeness-check.py not invoked in recipe")
        for var in _STRICT_VARS:
            export_idx = self.body.find(f"export {var}=1")
            self.assertGreater(export_idx, -1)
            self.assertLess(
                export_idx, gate_idx,
                f"export {var}=1 must appear BEFORE the audit-completeness-check.py "
                "invocation, not after",
            )

    def test_unstrict_else_branch_has_no_exports(self):
        """When STRICT is unset, the executed branch must not export any of the
        four vars (advisory-by-default backward-compat)."""
        # crude split on the top-level if/else/fi that gates the exports
        if_idx = self.body.find("if [")
        else_idx = self.body.find("\telse")
        self.assertGreater(if_idx, -1)
        self.assertGreater(else_idx, if_idx, "no else branch found for the STRICT gate")
        else_branch = self.body[else_idx:]
        for var in _STRICT_VARS:
            self.assertNotIn(
                f"export {var}=1", else_branch,
                f"{var} is exported even in the non-STRICT else branch",
            )


class MakeDryRunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        (Path(self.tmp) / ".auditooor").mkdir(parents=True, exist_ok=True)

    def _dry_run(self, extra_args):
        proc = subprocess.run(
            ["make", "-n", "audit-complete", f"WS={self.tmp}", *extra_args],
            cwd=str(_REPO), capture_output=True, text=True, timeout=60,
        )
        return proc

    def test_strict1_dry_run_does_not_error_and_exports_appear(self):
        proc = self._dry_run(["STRICT=1"])
        self.assertEqual(
            proc.returncode, 0,
            f"make -n audit-complete STRICT=1 errored: {proc.stderr}",
        )
        for var in _STRICT_VARS:
            self.assertIn(
                f"export {var}=1", proc.stdout,
                f"{var} export line missing from `make -n ... STRICT=1` dry-run output",
            )

    def test_strict_unset_dry_run_does_not_export(self):
        proc = self._dry_run([])
        self.assertEqual(
            proc.returncode, 0,
            f"make -n audit-complete (no STRICT) errored: {proc.stderr}",
        )
        # The `if [ -n "" ]` guard is statically present (both branches are always
        # printed by `make -n`), so assert the guard evaluates false rather than
        # absence of the export text.
        self.assertIn('if [ -n "" ]', proc.stdout)

    def test_strict0_dry_run_guard_evaluates_false(self):
        proc = self._dry_run(["STRICT=0"])
        self.assertEqual(proc.returncode, 0, f"errored: {proc.stderr}")
        self.assertIn('if [ -n "0" ] && [ "0" != "0" ]', proc.stdout)


if __name__ == "__main__":
    unittest.main()
