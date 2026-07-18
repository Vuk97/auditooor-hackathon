#!/usr/bin/env python3
"""End-to-end regression for the Go mutation-verify EMITTER (GAP 2).

Closes the serving-join gap where a genuine EXECUTED Go mutation-kill had no
canonical emitter writing the `.auditooor/mvc_sidecar/*.json` record that
`audit-honesty-check._mutation_verified_cut_harnesses` credits.

Unlike the hermetic `test_mutation_verify_coverage.py` (which drives a Python
stub harness) and `test_honesty_check_go_mvc_serving_join.py` (which synthesizes
a sidecar dict on disk), THIS test exercises the REAL toolchain end-to-end:
a tiny `go.mod` module, a real `go test` runner, the mutate -> re-run -> restore
loop, and the durable-sidecar writer - then asserts the honesty-check reader's
verdict. It is SKIPPED when `go` is not installed so the suite stays green
offline / in CI without a Go toolchain.

Two scenarios (the emitter's contract):
  (1) a harness that KILLS its mutant (TestSum exercises Sum) ->
      a valid mvc_sidecar (baseline pass + verdict non-vacuous + a real kill +
      CUT source_file on disk) that the reader CREDITS; and the CUT source is
      restored byte-clean after the run.
  (2) a VACUOUS harness (TestNothing never calls Sum, mutant survives) ->
      NO sidecar is written (verdict `vacuous`), so the reader credits nothing.
"""
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(mod_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(mod_name, str(_TOOLS / filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mvc = _load("mutation_verify_coverage", "mutation-verify-coverage.py")
ahc = _load("audit_honesty_check", "audit-honesty-check.py")

_GO = shutil.which("go")

_GO_MOD = "module mvcfix{tag}\n\ngo 1.20\n"
_CUT = (
    "package mvcfix{tag}\n\n"
    "// Sum returns a+b.\n"
    "func Sum(a, b int) int {{\n"
    "\treturn a + b\n"
    "}}\n"
)
# A harness that EXERCISES Sum: mutating `+`->`-` breaks the assertion (KILL).
_TEST_KILL = (
    "package mvcfix{tag}\n\n"
    "import \"testing\"\n\n"
    "func TestSum(t *testing.T) {{\n"
    "\tif Sum(2, 3) != 5 {{\n"
    "\t\tt.Fatalf(\"want 5 got %d\", Sum(2, 3))\n"
    "\t}}\n"
    "}}\n"
)
# A VACUOUS harness: never calls Sum, so every mutant of Sum SURVIVES.
_TEST_VACUOUS = (
    "package mvcfix{tag}\n\n"
    "import \"testing\"\n\n"
    "func TestNothing(t *testing.T) {{\n"
    "\tif 1+1 != 2 {{\n"
    "\t\tt.Fatal(\"math broke\")\n"
    "\t}}\n"
    "}}\n"
)


def _make_ws(root: Path, tag: str, test_body: str) -> Path:
    ws = root / tag
    (ws / ".auditooor").mkdir(parents=True)
    (ws / "go.mod").write_text(_GO_MOD.format(tag=tag), encoding="utf-8")
    (ws / "sum.go").write_text(_CUT.format(tag=tag), encoding="utf-8")
    (ws / "sum_test.go").write_text(test_body.format(tag=tag), encoding="utf-8")
    return ws


@unittest.skipUnless(_GO, "go toolchain not installed")
class TestGoMutationVerifySidecarEmitter(unittest.TestCase):
    def _verify(self, ws: Path):
        return mvc.verify(
            workspace=ws,
            source_file=ws / "sum.go",
            function="Sum",
            harness="go test ./...",
            language="go",
            timeout=300,
        )

    def test_killed_harness_writes_credited_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), "kill", _TEST_KILL)
            cut = ws / "sum.go"
            before = cut.read_bytes()

            rec = self._verify(ws)
            durable = mvc._persist_durable_sidecar(ws, rec)

            # non-vacuous verdict on a REAL executed go-test kill.
            self.assertEqual(rec["verdict"], "non-vacuous", rec.get("reason"))
            self.assertEqual(rec["baseline"]["status"], "pass")
            self.assertGreaterEqual(rec.get("killed_count", 0), 1)
            self.assertEqual(rec["language"], "go")
            # CUT restored byte-clean (git diff empty).
            self.assertEqual(cut.read_bytes(), before, "CUT not restored byte-clean")

            # A durable sidecar was written into the dir the gates read.
            self.assertIsNotNone(durable, "no durable sidecar persisted for a genuine kill")
            side_dir = ws / ".auditooor" / "mvc_sidecar"
            self.assertTrue(list(side_dir.glob("*.json")), "mvc_sidecar dir empty")

            # The honesty-check reader CREDITS it (the whole point of GAP 2).
            credited = ahc._mutation_verified_cut_harnesses(ws)
            self.assertTrue(
                any("sum.go" in c for c in credited),
                f"genuine Go kill not credited by reader: {credited}",
            )

    def test_vacuous_harness_is_not_credited(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(Path(td), "vac", _TEST_VACUOUS)
            cut = ws / "sum.go"
            before = cut.read_bytes()

            rec = self._verify(ws)
            durable = mvc._persist_durable_sidecar(ws, rec)

            # A harness that never exercises Sum is explicitly VACUOUS (its mutant
            # SURVIVES) - never non-vacuous, so it earns no coverage credit.
            self.assertNotEqual(rec["verdict"], "non-vacuous", rec.get("reason"))
            self.assertEqual(rec.get("survived_count"), 1)
            self.assertEqual(cut.read_bytes(), before, "CUT not restored byte-clean")

            # No credit record is persisted for a vacuous harness ...
            self.assertIsNone(durable, "vacuous harness must NOT persist a sidecar")
            side_dir = ws / ".auditooor" / "mvc_sidecar"
            self.assertFalse(
                side_dir.exists() and list(side_dir.glob("*.json")),
                "vacuous harness wrote a sidecar",
            )
            # ... and the reader credits nothing.
            self.assertEqual(ahc._mutation_verified_cut_harnesses(ws), [])


if __name__ == "__main__":
    unittest.main()
