"""Guard tests for tools/chimera-invariant-registrar.py

Failure modes protected:
  (A) PASS: A fixture harness with a manifest and a kill-test that PASSES gets a
      mutation_verified=true entry written to the canonical file.
  (B) FAIL-CLOSED (no kill tests): A harness whose forge output contains NO kill-pattern
      tests (empty output / compile error) does NOT get mutation_verified=true.
  (C) FAIL-CLOSED (kill test fails): A harness whose kill-pattern test FAILS in forge
      output does NOT get mutation_verified=true.
  (D) SKIP (no manifest): A harness directory without a chimera_cut_manifest.json is
      silently skipped (no entry written at all for it).
  (E) IDEMPOTENT MERGE: Re-running for the same harness replaces (not duplicates) the
      entry; running for a NEW harness preserves existing entries for prior harnesses.
  (F) DRY-RUN: --dry-run does not write the output file.
  (G) MANIFEST-ONLY: A harness with a manifest but whose forge emits no kill tests
      produces mutation_verified=false (pattern mismatch / absent tests).

The tests monkey-patch subprocess.run so no real forge is needed.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Load the tool module without executing main
# ---------------------------------------------------------------------------
_TOOL = Path(__file__).resolve().parents[1] / "chimera-invariant-registrar.py"


def _load_tool() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("chimera_invariant_registrar", str(_TOOL))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_mod = _load_tool()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_forge_stdout(pass_tests: list[str], fail_tests: list[str]) -> str:
    """Build a fake forge test output with the given PASS and FAIL lines."""
    lines = []
    for t in pass_tests:
        lines.append(f"    [PASS] {t}() (gas: 99999)")
    for t in fail_tests:
        lines.append(f"    [FAIL. Reason: assertion failed] {t}() (gas: 99999)")
    lines.append("Test result: ok. 0 failed; 0 passed")  # summary line (not parsed)
    return "\n".join(lines)


def _mock_proc(returncode: int, stdout: str, stderr: str = "") -> MagicMock:
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


def _make_harness(tmp: Path, name: str, with_manifest: bool, cut_files: list[str] | None = None) -> Path:
    """Create a minimal harness directory under tmp/chimera_harnesses/<name>/."""
    hdir = tmp / "chimera_harnesses" / name
    hdir.mkdir(parents=True, exist_ok=True)
    if with_manifest:
        manifest = {
            "cut_source_files": cut_files or ["contracts/Foo.sol"],
            "mutation_kill_test_pattern": "test_mutation_kills_|test_nonvacuity_",
        }
        (hdir / "chimera_cut_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return hdir


def _read_canonical(ws: Path) -> dict:
    p = ws / ".auditooor" / "mutation_verify_coverage.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestChimeraInvariantRegistrar(unittest.TestCase):

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = Path(tempfile.mkdtemp())
        self._ws = self._tmpdir
        self._ws_auditooor = self._ws / ".auditooor"
        self._ws_auditooor.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------
    # (A) Happy path: kill test PASSES -> mutation_verified=true
    # ------------------------------------------------------------------
    def test_A_kill_test_passes_writes_verified_entry(self) -> None:
        """A harness with a manifest + passing kill test gets mutation_verified=true."""
        _make_harness(self._ws, "MyInvariants", with_manifest=True, cut_files=["src/Foo.sol"])
        stdout = _fake_forge_stdout(
            pass_tests=["test_mutation_kills_foo"],
            fail_tests=[],
        )
        with patch("subprocess.run", return_value=_mock_proc(0, stdout)):
            rc = _mod.main(["--ws", str(self._ws)])

        self.assertEqual(rc, 0, "Expected rc=0 when all kill tests pass")
        doc = _read_canonical(self._ws)
        pf = doc.get("per_function", [])
        chimera = [r for r in pf if r.get("mode") == "chimera-invariant"]
        self.assertEqual(len(chimera), 1, "Expected exactly 1 chimera entry")
        entry = chimera[0]
        self.assertTrue(entry["mutation_verified"], "mutation_verified must be True")
        self.assertTrue(entry["killed"], "killed must be True")
        self.assertEqual(entry["oracle_verdict"], "non-vacuous")
        self.assertEqual(entry["verdict"], "killed")
        self.assertIn("test_mutation_kills_foo", entry["kill_test_names"])
        self.assertEqual(entry["function"], "MyInvariants")
        self.assertEqual(entry["source_file"], "src/Foo.sol")

    # ------------------------------------------------------------------
    # (B) FAIL-CLOSED: no kill-pattern tests in forge output
    # ------------------------------------------------------------------
    def test_B_no_kill_tests_in_output_not_verified(self) -> None:
        """forge exits 0 but no kill-pattern tests appear -> mutation_verified=false."""
        _make_harness(self._ws, "EmptyHarness", with_manifest=True)
        stdout = "    [PASS] test_some_other_test() (gas: 111)\nTest result: ok."
        with patch("subprocess.run", return_value=_mock_proc(0, stdout)):
            rc = _mod.main(["--ws", str(self._ws)])

        # rc=1 because not all harnesses produced verified entries
        self.assertEqual(rc, 1)
        doc = _read_canonical(self._ws)
        pf = doc.get("per_function", [])
        chimera = [r for r in pf if r.get("mode") == "chimera-invariant"]
        self.assertEqual(len(chimera), 1)
        self.assertFalse(chimera[0]["mutation_verified"], "Must be False when no kill tests found")

    # ------------------------------------------------------------------
    # (C) FAIL-CLOSED: kill test listed as FAIL in forge output
    # ------------------------------------------------------------------
    def test_C_kill_test_fails_in_forge_not_verified(self) -> None:
        """A kill-pattern test that FAILS in forge output must NOT produce verified=true."""
        _make_harness(self._ws, "FailHarness", with_manifest=True)
        stdout = _fake_forge_stdout(
            pass_tests=[],
            fail_tests=["test_mutation_kills_bad_invariant"],
        )
        # forge exits 1 when tests fail
        with patch("subprocess.run", return_value=_mock_proc(1, stdout)):
            rc = _mod.main(["--ws", str(self._ws)])

        self.assertEqual(rc, 1)
        doc = _read_canonical(self._ws)
        pf = doc.get("per_function", [])
        chimera = [r for r in pf if r.get("mode") == "chimera-invariant"]
        self.assertEqual(len(chimera), 1)
        self.assertFalse(chimera[0]["mutation_verified"], "FAIL in forge output => not verified")

    # ------------------------------------------------------------------
    # (D) SKIP: harness directory has no manifest
    # ------------------------------------------------------------------
    def test_D_no_manifest_harness_silently_skipped(self) -> None:
        """A harness dir without chimera_cut_manifest.json produces no entry."""
        _make_harness(self._ws, "NoManifest", with_manifest=False)
        with patch("subprocess.run", side_effect=AssertionError("forge should not be called")):
            rc = _mod.main(["--ws", str(self._ws)])

        self.assertEqual(rc, 0, "rc=0 when nothing to register")
        doc = _read_canonical(self._ws)
        # file may not even exist if nothing was registered
        pf = doc.get("per_function", [])
        chimera = [r for r in pf if r.get("mode") == "chimera-invariant"]
        self.assertEqual(len(chimera), 0, "No entry should exist for a manifest-less harness")

    # ------------------------------------------------------------------
    # (E) Idempotent merge: re-run replaces, new harness preserves old
    # ------------------------------------------------------------------
    def test_E_idempotent_merge_no_duplication(self) -> None:
        """Re-running for the same harness replaces the entry (no duplication)."""
        _make_harness(self._ws, "Stable", with_manifest=True, cut_files=["src/Stable.sol"])
        stdout = _fake_forge_stdout(pass_tests=["test_mutation_kills_x"], fail_tests=[])

        with patch("subprocess.run", return_value=_mock_proc(0, stdout)):
            _mod.main(["--ws", str(self._ws)])
        # Run again - should not duplicate
        with patch("subprocess.run", return_value=_mock_proc(0, stdout)):
            _mod.main(["--ws", str(self._ws)])

        doc = _read_canonical(self._ws)
        chimera = [r for r in doc.get("per_function", []) if r.get("mode") == "chimera-invariant"]
        self.assertEqual(len(chimera), 1, "Idempotent run must not duplicate the entry")
        self.assertTrue(chimera[0]["mutation_verified"])

    def test_E2_new_harness_preserves_existing_entry(self) -> None:
        """Adding a second harness preserves the first harness's entry."""
        _make_harness(self._ws, "Harness1", with_manifest=True, cut_files=["src/A.sol"])
        _make_harness(self._ws, "Harness2", with_manifest=True, cut_files=["src/B.sol"])
        stdout = _fake_forge_stdout(pass_tests=["test_mutation_kills_x"], fail_tests=[])

        # Run only Harness1 first
        with patch("subprocess.run", return_value=_mock_proc(0, stdout)):
            _mod.main(["--ws", str(self._ws), "--harness", "Harness1"])

        doc1 = _read_canonical(self._ws)
        pf1 = [r for r in doc1.get("per_function", []) if r.get("mode") == "chimera-invariant"]
        self.assertEqual(len(pf1), 1)
        self.assertEqual(pf1[0]["function"], "Harness1")

        # Now run only Harness2 - Harness1 must be preserved
        with patch("subprocess.run", return_value=_mock_proc(0, stdout)):
            _mod.main(["--ws", str(self._ws), "--harness", "Harness2"])

        doc2 = _read_canonical(self._ws)
        pf2 = [r for r in doc2.get("per_function", []) if r.get("mode") == "chimera-invariant"]
        names = {r["function"] for r in pf2}
        self.assertIn("Harness1", names, "Harness1 must be preserved after Harness2 run")
        self.assertIn("Harness2", names)

    # ------------------------------------------------------------------
    # (F) DRY-RUN: does not write the output file
    # ------------------------------------------------------------------
    def test_F_dry_run_does_not_write(self) -> None:
        """--dry-run must not create/modify the canonical file."""
        _make_harness(self._ws, "DryHarness", with_manifest=True)
        stdout = _fake_forge_stdout(pass_tests=["test_mutation_kills_x"], fail_tests=[])
        canonical = self._ws / ".auditooor" / "mutation_verify_coverage.json"
        self.assertFalse(canonical.exists(), "File should not exist before dry run")

        with patch("subprocess.run", return_value=_mock_proc(0, stdout)):
            _mod.main(["--ws", str(self._ws), "--dry-run"])

        self.assertFalse(canonical.exists(), "--dry-run must not write the canonical file")

    # ------------------------------------------------------------------
    # (G) MANIFEST present but forge emits no kill tests (pattern mismatch)
    # ------------------------------------------------------------------
    def test_G_custom_pattern_mismatch_not_verified(self) -> None:
        """A manifest with a kill pattern that matches nothing in forge output -> not verified."""
        hdir = _make_harness(self._ws, "PatternMismatch", with_manifest=False)
        manifest = {
            "cut_source_files": ["contracts/Bar.sol"],
            "mutation_kill_test_pattern": "test_nonvacuity_",  # narrow pattern
        }
        (hdir / "chimera_cut_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        # Forge output has a kill test under the DEFAULT pattern but not test_nonvacuity_
        stdout = _fake_forge_stdout(pass_tests=["test_mutation_kills_bar"], fail_tests=[])
        with patch("subprocess.run", return_value=_mock_proc(0, stdout)):
            rc = _mod.main(["--ws", str(self._ws)])

        self.assertEqual(rc, 1)
        doc = _read_canonical(self._ws)
        chimera = [r for r in doc.get("per_function", []) if r.get("mode") == "chimera-invariant"]
        self.assertEqual(len(chimera), 1)
        self.assertFalse(chimera[0]["mutation_verified"],
                         "Pattern mismatch must produce mutation_verified=false")

    # ------------------------------------------------------------------
    # Schema / structure sanity
    # ------------------------------------------------------------------
    def test_schema_field_present(self) -> None:
        """The written file must have the correct schema field."""
        _make_harness(self._ws, "SchemaCheck", with_manifest=True)
        stdout = _fake_forge_stdout(pass_tests=["test_mutation_kills_y"], fail_tests=[])
        with patch("subprocess.run", return_value=_mock_proc(0, stdout)):
            _mod.main(["--ws", str(self._ws)])

        doc = _read_canonical(self._ws)
        self.assertEqual(doc.get("schema"), "auditooor.mutation_verify_coverage.v1")
        self.assertIn("counts", doc)
        self.assertIn("per_function_total", doc["counts"])
        self.assertIn("per_function_verified", doc["counts"])

    def test_existing_per_function_non_chimera_preserved(self) -> None:
        """Existing non-chimera per_function entries must be preserved after a chimera run."""
        # Seed the canonical file with a source-recompile entry
        seed = {
            "schema": "auditooor.mutation_verify_coverage.v1",
            "per_function": [
                {
                    "axis": "per-function",
                    "mode": "source-recompile",
                    "function": "transfer",
                    "mutation_verified": False,
                    "verdict": "vacuous",
                }
            ],
            "cross_function": [],
            "counts": {},
        }
        (self._ws_auditooor / "mutation_verify_coverage.json").write_text(
            json.dumps(seed), encoding="utf-8"
        )

        _make_harness(self._ws, "NewChimera", with_manifest=True)
        stdout = _fake_forge_stdout(pass_tests=["test_mutation_kills_z"], fail_tests=[])
        with patch("subprocess.run", return_value=_mock_proc(0, stdout)):
            _mod.main(["--ws", str(self._ws)])

        doc = _read_canonical(self._ws)
        pf = doc.get("per_function", [])
        modes = {r.get("mode") for r in pf}
        self.assertIn("source-recompile", modes, "Pre-existing source-recompile entry must be preserved")
        self.assertIn("chimera-invariant", modes, "New chimera entry must be added")


if __name__ == "__main__":
    unittest.main(verbosity=2)
