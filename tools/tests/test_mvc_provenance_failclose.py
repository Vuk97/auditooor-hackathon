"""Generic capability fix (2026-07-13): fail-CLOSED sidecar-provenance crediting.

Two defects let a mutation-verify sidecar credit the strict gate on unattested
evidence:

  DEFECT A - STALE HARNESS (sha drift): a sidecar stamps harness_source_sha256 at
  mutation-kill time, but the on-disk harness is later edited, so the recorded kill
  no longer attests the current harness. The provenance reader credited it anyway.

  DEFECT B - UNATTESTED MANUAL RECORDS: a manual_registration=true record whose only
  registration anti-fake check is "harness_path exists" can set
  mutation_verified=true / verdict='non-vacuous' with agent-authored output strings
  and NO captured baseline runner output (source_file='', baseline_result=None).

The fix lives at the READER/credit layer (shared lib predicates
tools/lib/mutation_kill.py: sidecar_harness_drifted / sidecar_manual_attested /
sidecar_uncredited_reason, consumed by audit-honesty-check.py). It is GENERIC (any
workspace/language) and does NOT delete or mutate a workspace's sidecars.

Cases:
  (a) matching-sha runner sidecar             => credited (reason None)
  (b) drifted-sha sidecar                      => NOT credited + drift reason
  (c) manual_registration empty source / no baseline => NOT credited + manual reason
  (d) manual_registration WITH real source_file + captured baseline => credited
"""
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load_lib():
    spec = importlib.util.spec_from_file_location(
        "mutation_kill", str(_TOOLS / "lib" / "mutation_kill.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mutation_kill"] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_reader():
    spec = importlib.util.spec_from_file_location(
        "ahc_ct", str(_TOOLS / "audit-honesty-check.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ahc_ct"] = mod
    spec.loader.exec_module(mod)
    return mod


def _genuine_kill_fields():
    """Minimal fields that make sidecar_is_genuine True (non-vacuous + a real kill)."""
    return {"verdict": "non-vacuous", "mutants_killed": 1}


class TestMvcProvenanceFailClose(unittest.TestCase):
    def setUp(self):
        self.lib = _load_lib()
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        # A real on-disk harness whose content is stamped by the matching record.
        self.harness = self.ws / "test" / "Invariant_test.go"
        self.harness.parent.mkdir(parents=True, exist_ok=True)
        self.harness.write_text("package x // real harness body\n", encoding="utf-8")
        self.harness_sha = hashlib.sha256(
            self.harness.read_bytes()).hexdigest()
        # A real on-disk source file for the manual-attested case.
        self.src = self.ws / "src" / "vault.go"
        self.src.parent.mkdir(parents=True, exist_ok=True)
        self.src.write_text("package vault\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    # ---- case (a): matching-sha runner sidecar => credited -----------------
    def test_a_matching_sha_credited(self):
        rec = dict(_genuine_kill_fields())
        rec["harness_path"] = "test/Invariant_test.go"
        rec["harness_source_sha256"] = self.harness_sha
        self.assertTrue(self.lib.sidecar_is_genuine(rec))
        self.assertFalse(self.lib.sidecar_harness_drifted(rec, self.ws))
        self.assertIsNone(self.lib.sidecar_uncredited_reason(rec, self.ws))

    # ---- case (b): drifted-sha sidecar => NOT credited + reason -------------
    def test_b_drifted_sha_uncredited(self):
        rec = dict(_genuine_kill_fields())
        rec["harness_path"] = "test/Invariant_test.go"
        rec["harness_source_sha256"] = "deadbeef" * 8  # stale, != on-disk
        self.assertTrue(self.lib.sidecar_is_genuine(rec))  # genuine kill, but...
        self.assertTrue(self.lib.sidecar_harness_drifted(rec, self.ws))
        reason = self.lib.sidecar_uncredited_reason(rec, self.ws)
        self.assertIsNotNone(reason)
        self.assertIn("drift", reason)

    # ---- case (c): manual, empty source / no baseline => NOT credited -------
    def test_c_manual_unattested_uncredited(self):
        rec = dict(_genuine_kill_fields())
        rec["mode"] = "manual-mutant-harness"
        rec["manual_registration"] = True
        rec["source_file"] = ""            # empty
        rec["baseline_result"] = None      # no captured runner output
        rec["baseline_output_tail"] = None
        rec["harness_path"] = "test/Invariant_test.go"
        rec["harness_source_sha256"] = self.harness_sha  # sha OK - manual is the fail
        self.assertFalse(self.lib.sidecar_manual_attested(rec, self.ws))
        reason = self.lib.sidecar_uncredited_reason(rec, self.ws)
        self.assertIsNotNone(reason)
        self.assertIn("manual", reason)

    def test_c2_manual_source_set_but_no_baseline_uncredited(self):
        # source_file exists on disk, but NO baseline captured -> still uncredited.
        rec = dict(_genuine_kill_fields())
        rec["manual_registration"] = True
        rec["source_file"] = "src/vault.go"
        rec["baseline_result"] = None
        rec["baseline_output_tail"] = None
        self.assertFalse(self.lib.sidecar_manual_attested(rec, self.ws))
        self.assertIsNotNone(self.lib.sidecar_uncredited_reason(rec, self.ws))

    # ---- case (d): manual WITH real source + captured baseline => credited --
    def test_d_manual_attested_credited(self):
        rec = dict(_genuine_kill_fields())
        rec["mode"] = "manual-mutant-harness"
        rec["manual_registration"] = True
        rec["source_file"] = "src/vault.go"       # exists on disk
        rec["baseline_result"] = "pass"           # real captured runner result
        rec["baseline_output_tail"] = "ok  vault  0.5s\nPASS"
        self.assertTrue(self.lib.sidecar_manual_attested(rec, self.ws))
        self.assertIsNone(self.lib.sidecar_uncredited_reason(rec, self.ws))

    # ---- non-manual records are NOT gated by the manual predicate ----------
    def test_non_manual_not_gated_by_manual_check(self):
        rec = dict(_genuine_kill_fields())
        rec["harness_path"] = "test/Invariant_test.go"
        rec["harness_source_sha256"] = self.harness_sha
        self.assertTrue(self.lib.sidecar_manual_attested(rec, self.ws))

    # ---- reader-level end-to-end: drifted + manual records drop out --------
    def test_reader_credit_drops_drifted_and_manual(self):
        reader = _load_reader()
        sc = self.ws / ".auditooor" / "mvc_sidecar"
        sc.mkdir(parents=True, exist_ok=True)

        def _write(name, extra):
            rec = dict(_genuine_kill_fields())
            rec.update(extra)
            (sc / name).write_text(json.dumps(rec), encoding="utf-8")

        # credited: matching-sha runner sidecar over a real on-disk CUT.
        _write("good.json", {
            "harness_path": "test/Invariant_test.go",
            "harness_source_sha256": self.harness_sha,
            "source_file": "src/vault.go",
            "function": "deposit",
        })
        # NOT credited: drifted.
        _write("drift.json", {
            "harness_path": "test/Invariant_test.go",
            "harness_source_sha256": "cafe" * 16,
            "source_file": "src/vault.go",
            "function": "withdraw",
        })
        # NOT credited: manual-unattested.
        _write("manual.json", {
            "manual_registration": True,
            "source_file": "",
            "baseline_result": None,
            "baseline_output_tail": None,
            "harness_path": "test/Invariant_test.go",
            "function": "reconcile",
        })
        credited = reader._mutation_verified_cut_harnesses(self.ws)
        # exactly the one genuine, matching-sha, attested record is credited.
        self.assertEqual(len(credited), 1, credited)
        self.assertTrue(any("Invariant_test.go" in c for c in credited))


if __name__ == "__main__":
    unittest.main()
