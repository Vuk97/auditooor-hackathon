"""Guard: `make hunt-scoped` runs the pre-hunt ENUMERATION producers (which
materialize the FULL in-scope-unit x impact-frame coverage plane) BEFORE it
builds the scoped-hunt plan, but ONLY when the operator opts in via
AUDITOOOR_PREHUNT_MATRIX / AUDITOOOR_PLANE_DRAIN.

THE GAP this closes: the enumerate-BEFORE-hunt producers only ran inside
`make audit-pipeline-full` (audit-deep materializes coverage_plane.jsonl via
tools/coverage-plane-build.py, STEP 2.9 runs the completeness enumerate). The
canonical loop entry `make hunt-scoped` never ran them, so on a cold / stale
workspace the A2 plane-drain in per-fn-mimo-batch-gen.py /
inscope-hunt-batch-builder.py had NO .auditooor/coverage_plane.jsonl to drain and
the hunt scoped only to the coverage-RESIDUAL units instead of the FULL
(in-scope unit x impact-frame) not-enumerated surface (Primacy-of-Impact).

This test asserts, statically on the Makefile recipe body AND via `make -n`:

  1. hunt-scoped dispatches the _hunt-prehunt-enum sub-target BEFORE
     haiku-harness-plan (the plan builder). The gate is DEFAULT-ON now: env-unset
     dispatches, explicit 0/false/no suppresses, and opt-in drain remains additive.
  2. BYTE-PARITY for the new contract: explicit opt-out `make -n hunt-scoped
     AUDITOOOR_PREHUNT_MATRIX=0 AUDITOOOR_PLANE_DRAIN=0` does NOT dispatch
     _hunt-prehunt-enum and does NOT name any of the 3 enumeration producers.
     Env-unset dispatches the sub-target by default, and explicit opt-in remains a
     superset of the opt-out stream.
  3. The _hunt-prehunt-enum recipe invokes the three producers the drivers
     already use -- coverage-plane-build.py --workspace,
     completeness-matrix-build.py --workspace ... --enumerate-only, and
     mechanism-scan-run.py --workspace -- each `||`-guarded WARN-and-continue
     (non-fatal, no --strict), staleness-guarded (only (re)runs when the plane is
     absent or older than inscope_units.jsonl).

Generic: no workspace name / language / target path is hardcoded.
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"

# The three enumeration producers, with the exact flags the drivers already use.
_PLANE_BUILD = "coverage-plane-build.py"
_MATRIX_ENUM = "completeness-matrix-build.py"
_MECH_SCAN = "mechanism-scan-run.py"


def _recipe_block(text: str, target: str) -> str:
    """Return the recipe body for `target:` up to (excluding) the next
    top-level (non-indented) Makefile construct line."""
    lines = text.splitlines()
    out, capturing = [], False
    for ln in lines:
        if re.match(rf"^{re.escape(target)}(\s|:)", ln) and ":" in ln:
            capturing = True
            out.append(ln)
            continue
        if capturing:
            if ln and not ln.startswith(("\t", " ")) and re.match(r"^[A-Za-z0-9_.-]+\s*:", ln):
                break
            out.append(ln)
    return "\n".join(out)


def _make_n(env_extra, ws, target="hunt-scoped"):
    import os
    env = dict(os.environ)
    env.update(env_extra)
    return subprocess.run(
        ["make", "-n", target, f"WS={ws}"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, env=env,
    )


class TestHuntScopedPrehuntEnumWiring(unittest.TestCase):
    def setUp(self):
        self.text = MAKEFILE.read_text(encoding="utf-8")
        self.hunt_block = _recipe_block(self.text, "hunt-scoped hunt-haiku")
        self.assertTrue(self.hunt_block, "hunt-scoped recipe not found in Makefile")
        self.enum_block = _recipe_block(self.text, "_hunt-prehunt-enum")
        self.assertTrue(self.enum_block, "_hunt-prehunt-enum recipe not found in Makefile")

    # --- static: hunt-scoped dispatches the sub-target, make-level gated ---------

    def test_hunt_scoped_dispatches_prehunt_enum_gated(self):
        # The dispatch is a $(if $(_PREHUNT_ENUM_ON),...) -> make-level gated.
        self.assertIn(
            "_hunt-prehunt-enum", self.hunt_block,
            "hunt-scoped must dispatch the _hunt-prehunt-enum sub-target (the "
            "pre-hunt enumeration that materializes coverage_plane.jsonl)",
        )
        self.assertRegex(
            self.hunt_block,
            r"\$\(if\s+\$\(_PREHUNT_ENUM_ON\)\s*,[\s\S]*_hunt-prehunt-enum",
            "the _hunt-prehunt-enum dispatch must be wrapped in "
            "$(if $(_PREHUNT_ENUM_ON),...) so the make-level gate owns dispatch "
            "instead of a runtime shell if",
        )

    def test_prehunt_enum_dispatch_precedes_plan_build(self):
        di = self.hunt_block.find("_hunt-prehunt-enum")
        pi = self.hunt_block.find("haiku-harness-plan")
        self.assertGreater(di, -1)
        self.assertGreater(pi, -1, "hunt-scoped must still build the plan via haiku-harness-plan")
        self.assertLess(
            di, pi,
            "the _hunt-prehunt-enum dispatch must PRECEDE the haiku-harness-plan "
            "build so the plane exists before the A2 plane-drain reads it",
        )

    def test_prehunt_enum_on_var_defined_from_default_on_envs(self):
        # _PREHUNT_ENUM_ON defaults AUDITOOOR_PREHUNT_MATRIX to 1, still honoring
        # explicit 0/false/no and additive AUDITOOOR_PLANE_DRAIN truthiness.
        self.assertRegex(
            self.text,
            r"_PREHUNT_ENUM_ON\s*:?=\s*\$\(strip\s+\$\(filter-out\s+0\s+false\s+no\s*,\s*\$\(or\s+\$\(AUDITOOOR_PREHUNT_MATRIX\),1\)\)"
            r"\s+\$\(filter-out\s+0\s+false\s+no\s*,\s*\$\(AUDITOOOR_PLANE_DRAIN\)\)\)",
            "_PREHUNT_ENUM_ON must default AUDITOOOR_PREHUNT_MATRIX to 1 while "
            "still honoring explicit 0/false/no and additive PLANE_DRAIN truthiness",
        )

    # --- static: the sub-target runs the 3 producers, non-fatal + stale-guarded --

    def test_enum_invokes_three_producers_with_driver_flags(self):
        self.assertRegex(
            self.enum_block,
            rf"python3 tools/{re.escape(_PLANE_BUILD)}\s+--workspace\s+\"\$\(_WS_RESOLVED\)\"",
            "must invoke coverage-plane-build.py --workspace $(_WS_RESOLVED) "
            "(the producer that writes coverage_plane.jsonl, same as audit-deep)",
        )
        self.assertRegex(
            self.enum_block,
            rf"python3 tools/{re.escape(_MATRIX_ENUM)}\s+--workspace\s+\"\$\(_WS_RESOLVED\)\"\s+--enumerate-only",
            "must invoke completeness-matrix-build.py --workspace ... "
            "--enumerate-only (the STEP 2.9 enumerate producer)",
        )
        self.assertRegex(
            self.enum_block,
            rf"python3 tools/{re.escape(_MECH_SCAN)}\s+--workspace\s+\"\$\(_WS_RESOLVED\)\"",
            "must invoke mechanism-scan-run.py --workspace $(_WS_RESOLVED) "
            "(best-effort mechanism sidecars)",
        )

    def test_enum_producers_are_non_fatal_no_strict(self):
        # Each producer is || -guarded into a WARN-and-continue, no --strict.
        for prod in (_PLANE_BUILD, _MATRIX_ENUM, _MECH_SCAN):
            idx = self.enum_block.find(f"tools/{prod}")
            self.assertGreater(idx, -1, f"{prod} not found in _hunt-prehunt-enum")
            snippet = self.enum_block[idx: idx + 300]
            first_line = snippet.splitlines()[0]
            self.assertNotIn(
                "--strict", first_line,
                f"{prod} must be invoked WITHOUT --strict so the pre-hunt "
                f"enumeration stays advisory (never fail-close the hunt)",
            )
            self.assertIn(
                "||", snippet,
                f"{prod} must be || -guarded (non-fatal, warn-and-continue), "
                f"mirroring the audit-deep advisory posture",
            )
            self.assertIn(
                "WARN", snippet,
                f"{prod} failure path must emit a WARN, not fail-close the recipe",
            )

    def test_enum_is_staleness_guarded(self):
        # Only (re)runs the producers when the plane is ABSENT or older than
        # inscope_units.jsonl (so a warm re-run is cheap).
        self.assertIn("coverage_plane.jsonl", self.enum_block)
        self.assertIn("inscope_units.jsonl", self.enum_block)
        self.assertRegex(
            self.enum_block,
            r"\[\s+!\s+-f\s+\"\$\$_plane\"\s+\]\s+\|\|\s+\{\s+\[\s+-f\s+\"\$\$_inscope\"\s+\]\s+&&\s+\[\s+\"\$\$_inscope\"\s+-nt\s+\"\$\$_plane\"\s+\]",
            "the sub-target must guard the producers behind an absent-or-stale "
            "check ([ ! -f plane ] || inscope -nt plane) so warm re-runs are cheap",
        )

    # --- dynamic: make -n byte-parity (env-unset) vs superset (env-set) ----------

    def test_dry_run_default_on_opt_out_and_superset(self):
        if not shutil.which("make"):
            self.skipTest("make not available on PATH")
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "throwaway_ws"
            (ws / ".auditooor").mkdir(parents=True)

            disabled = _make_n({"AUDITOOOR_PREHUNT_MATRIX": "0", "AUDITOOOR_PLANE_DRAIN": "0"}, ws)
            self.assertEqual(disabled.returncode, 0, f"opt-out make -n must parse clean:\n{disabled.stderr}")

            unset = _make_n({"AUDITOOOR_PREHUNT_MATRIX": "", "AUDITOOOR_PLANE_DRAIN": ""}, ws)
            self.assertEqual(unset.returncode, 0, f"env-unset make -n must parse clean:\n{unset.stderr}")

            def cmd_lines(out):
                # command lines only (drop pure `#` comments + blanks); a command
                # line that actually dispatches the sub-target or a producer.
                return [l for l in out.splitlines()
                        if l.strip() and not l.lstrip().startswith("#")]

            disabled_cmds = cmd_lines(disabled.stdout)
            # Explicit opt-out must suppress the sub-target and the producers.
            self.assertFalse(
                any("_hunt-prehunt-enum WS=" in l for l in disabled_cmds),
                "AUDITOOOR_PREHUNT_MATRIX=0 must suppress _hunt-prehunt-enum dispatch",
            )

            unset_cmds = cmd_lines(unset.stdout)
            self.assertTrue(
                any("_hunt-prehunt-enum WS=" in l for l in unset_cmds),
                "env-unset make -n must dispatch _hunt-prehunt-enum by default",
            )

            setrun = _make_n({"AUDITOOOR_PREHUNT_MATRIX": "1", "AUDITOOOR_PLANE_DRAIN": "1"}, ws)
            self.assertEqual(setrun.returncode, 0, f"env-set make -n must parse clean:\n{setrun.stderr}")
            set_cmds = cmd_lines(setrun.stdout)
            # SUPERSET: env-set dispatches the sub-target...
            self.assertTrue(
                any("_hunt-prehunt-enum WS=" in l for l in set_cmds),
                "env-set make -n must dispatch _hunt-prehunt-enum before the plan build",
            )
            # ...and (via the recursed sub-target) names all three producers.
            for prod in (_PLANE_BUILD, _MATRIX_ENUM, _MECH_SCAN):
                self.assertTrue(
                    any(f"tools/{prod}" in l for l in set_cmds),
                    f"env-set make -n must name {prod} (materialized before the hunt)",
                )
            # env-unset is a strict superset of the explicit opt-out stream, and
            # env-set is a superset of env-unset.
            missing = [l for l in disabled_cmds if l not in unset_cmds]
            self.assertEqual(
                missing, [],
                "env-unset command stream must be a SUPERSET of the explicit opt-out "
                f"stream; missing:\n{missing}",
            )
            missing = [l for l in unset_cmds if l not in set_cmds]
            self.assertEqual(
                missing, [],
                "env-set command stream must be a SUPERSET of env-unset; missing:\n"
                f"{missing}",
            )


if __name__ == "__main__":
    unittest.main()
