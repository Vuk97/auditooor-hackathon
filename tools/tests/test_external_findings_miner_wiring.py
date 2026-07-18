"""Wave-2 #10 wiring guard for tools/external-findings-miner.py.

Asserts that the miner's --to-derived flag emits the invariant + detector
seed into the canonical derived/<router>/<batch>/ dirs that the EXISTING
promote-mined-to-canonical SOURCE_ROUTERS (invariant_library_extended +
detector_synthesis_v2) scan, so a dry-run promotion picks them up.

Fail-before / pass-after discipline: the same promotion against a derived
root populated WITHOUT --to-derived (only --out-dir) yields 0 promoted - that
is the pre-fix state this wiring closes.

M14: uses the real reentrancy fixture
(tools/tests/fixtures/external_findings_miner/reentrancy_solodit.md); no
fabricated finding text.
"""
import importlib.util
import subprocess
import sys
import tempfile
import shutil
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MINER = ROOT / "tools" / "external-findings-miner.py"
PROMOTER = ROOT / "tools" / "promote-mined-to-canonical.py"
FIX = ROOT / "tools" / "tests" / "fixtures" / "external_findings_miner" / "reentrancy_solodit.md"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestExternalFindingsMinerWiring(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="efm_wiring_"))
        self.derived = self.tmp / "derived"
        self.prom = _load(PROMOTER, "prom_efm")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_miner(self, *extra):
        cmd = [sys.executable, str(MINER), "--family", "reentrancy",
               "--findings-md", str(FIX)] + list(extra)
        return subprocess.run(cmd, capture_output=True, text=True)

    def _routers(self):
        inv = {
            "name": "invariant_library_extended",
            "kind": "invariant",
            "source_dir": self.derived / "invariant_library_extended",
            "glob": "**/*.yaml",
            "dst_path": self.tmp / "inv_dst.jsonl",
            "key_field": "invariant_id",
            "extractor": self.prom._extract_invariant_library_extended,
        }
        det = {
            "name": "detector_synthesis_v2",
            "kind": "detector_seed",
            "source_dir": self.derived / "detector_synthesis_v2",
            "glob": "**/*.json",
            "dst_path": self.tmp / "det_dst.jsonl",
            "key_field": "record_id",
            "extractor": lambda r, s, b: self.prom._extract_dispatch_ledger_generic(
                r, s, b, kind="detector_seed"),
        }
        return inv, det

    def test_to_derived_outputs_are_promoted(self):
        # 1) mine into the tmp derived root via the NEW --to-derived flag.
        res = self._run_miner("--to-derived", str(self.derived))
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(
            (self.derived / "invariant_library_extended").is_dir(),
            "miner did not create the invariant_library_extended derived dir")
        self.assertTrue(
            (self.derived / "detector_synthesis_v2").is_dir(),
            "miner did not create the detector_synthesis_v2 derived dir")

        # 2) dry-run promote through the REAL routers/extractors.
        inv_router, det_router = self._routers()
        inv_promoted, _ = self.prom.promote_from_router(
            inv_router, min_conf="low", only_batch=None, dry_run=True)
        det_promoted, _ = self.prom.promote_from_router(
            det_router, min_conf="low", only_batch=None, dry_run=True)
        self.assertGreaterEqual(inv_promoted, 1,
                                "no invariant promoted from --to-derived output")
        self.assertGreaterEqual(det_promoted, 1,
                                "no detector_seed promoted from --to-derived output")

    def test_family_attack_class_present_in_promoted_records(self):
        res = self._run_miner("--to-derived", str(self.derived))
        self.assertEqual(res.returncode, 0, res.stderr)
        inv_router, det_router = self._routers()

        # Invariant: extractor preserves a category (family-derived).
        inv_files = sorted((self.derived / "invariant_library_extended").rglob("*.yaml"))
        self.assertTrue(inv_files)
        rec = self.prom._extract_record_content_from_ingested_yaml(inv_files[0])
        out = inv_router["extractor"](rec, inv_files[0], "batch")
        self.assertTrue(out and out[0].get("category"),
                        "promoted invariant lacks a category")

        # Detector seed: the family attack_class survives the generic extractor.
        det_files = sorted((self.derived / "detector_synthesis_v2").rglob("*.json"))
        self.assertTrue(det_files)
        drec = self.prom._extract_record_content_from_ingested_yaml(det_files[0])
        dout = det_router["extractor"](drec, det_files[0], "batch")
        self.assertTrue(dout, "detector seed produced no canonical record")
        self.assertEqual(dout[0].get("category"), "reentrancy",
                         "family attack_class 'reentrancy' not carried through")

    def test_pre_fix_state_yields_zero(self):
        # Mining WITHOUT --to-derived (the pre-fix behaviour, only --out-dir)
        # leaves the canonical derived routers empty -> 0 promoted. This is the
        # gap the wiring closes; if a future edit drops --to-derived this test
        # makes the regression observable.
        outdir = self.tmp / "legacy_out"
        res = self._run_miner("--out-dir", str(outdir))
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(outdir.is_dir())
        inv_router, det_router = self._routers()  # point at the EMPTY derived root
        inv_promoted, _ = self.prom.promote_from_router(
            inv_router, min_conf="low", only_batch=None, dry_run=True)
        det_promoted, _ = self.prom.promote_from_router(
            det_router, min_conf="low", only_batch=None, dry_run=True)
        self.assertEqual(inv_promoted, 0)
        self.assertEqual(det_promoted, 0)


if __name__ == "__main__":
    unittest.main()
